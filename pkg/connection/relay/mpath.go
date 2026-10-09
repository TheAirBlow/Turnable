package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/mpath"
	"github.com/theairblow/turnable/pkg/protocol"
)

// mpathAuthRoute is the reserved route index of the auth stream, always the first stream of a session
const mpathAuthRoute byte = 0xFF

// mpathClientState is the live client-side multipath session
type mpathClientState struct {
	mux *mpath.Mux
	cfg *ClientConfig
}

// mpathConfig builds the transport config shared by client and server
func mpathConfig(log *slog.Logger) mpath.Config {
	return mpath.Config{Grace: connection.SessionGrace, Logger: log}
}

// notifyConn reports when the session closes a path conn, so its slot can redial
type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// startMpathClient runs the peer slots, authenticates on the first stream and publishes the session
func (D *Handler) startMpathClient(
	sessionCtx context.Context,
	cfg *ClientConfig,
	numPeers int,
	dialRaw func(ctx context.Context, idx int) (net.Conn, error),
	fullReconnect func(string),
	connEvents *connection.EventStream,
) error {
	cli, err := mpath.NewClient(cfg.PubKey, mpathConfig(D.log))
	if err != nil {
		return fmt.Errorf("%w: %w", connection.ErrFatal, err)
	}

	slotErr := make(chan error, numPeers)
	for idx := 0; idx < numPeers; idx++ {
		go D.runMpathSlot(sessionCtx, cli, idx, dialRaw, fullReconnect, slotErr)
	}

	waitCtx, cancel := context.WithTimeout(sessionCtx, 3*relayHandshakeTimeout)
	defer cancel()
	sessCh := make(chan *mpath.Session, 1)
	go func() {
		if s, err := cli.WaitSession(waitCtx); err == nil {
			sessCh <- s
		}
	}()
	var sess *mpath.Session
	select {
	case err := <-slotErr:
		return err
	case sess = <-sessCh:
	case <-waitCtx.Done():
		if sessionCtx.Err() == nil {
			return errors.New("mpath handshake timeout: no peer completed the handshake (server down, or server too old for mux=mpath)")
		}
		return sessionCtx.Err()
	}
	sess.SetPathHandlers(func(c net.Conn) { _ = c.Close() }, nil)

	mux, err := mpath.NewClientMux(sess)
	if err != nil {
		_ = sess.Close()
		return err
	}
	sessionUUID, err := mpathClientAuth(waitCtx, mux, cfg)
	if err != nil {
		_ = mux.Close()
		var ackErr *ErrAckRejected
		if errors.As(err, &ackErr) {
			D.log.Error("server rejected authorization, stopping", "error", err)
			return fmt.Errorf("%w: %w", connection.ErrFatal, err)
		}
		return err
	}

	go func() {
		select {
		case <-mux.Done():
			if sessionCtx.Err() == nil {
				fullReconnect(fmt.Sprintf("mpath session ended: %v", sess.Err()))
			}
		case <-sessionCtx.Done():
			_ = mux.Close()
		}
	}()

	D.stateMu.Lock()
	D.mpath = &mpathClientState{mux: mux, cfg: cfg}
	D.sessionUUID = sessionUUID
	D.stateMu.Unlock()
	D.log.Info("relay mpath session established", "session_uuid", sessionUUID, "peers", numPeers)
	return nil
}

// runMpathSlot keeps one peer connection attached to the session, redialing with backoff
func (D *Handler) runMpathSlot(
	ctx context.Context,
	cli *mpath.Client,
	idx int,
	dialRaw func(ctx context.Context, idx int) (net.Conn, error),
	fullReconnect func(string),
	slotErr chan<- error,
) {
	log := D.log.With("peer_idx", idx)
	delay := time.Duration(0)
	for {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		if ctx.Err() != nil {
			return
		}
		if s := cli.Session(); s != nil && s.Err() != nil {
			return // the session is over; a full reconnect builds a new one
		}

		raw, err := dialRaw(ctx, idx)
		if err == nil {
			addCtx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
			conn := &notifyConn{Conn: raw, closed: make(chan struct{})}
			err = cli.AddPath(addCtx, conn)
			cancel()
			if err == nil {
				onlineAt := time.Now()
				log.Info("peer online")
				select {
				case <-conn.closed:
				case <-ctx.Done():
					return
				}
				log.Info("peer offline")
				if time.Since(onlineAt) >= peerStableAfter {
					delay = 0
				} else {
					delay = nextPeerDelay(delay)
				}
				continue
			}
			_ = raw.Close()
			switch {
			case errors.Is(err, mpath.ErrVersion):
				slotErr <- fmt.Errorf("%w: %w (upgrade the client and server together, or set mux=legacy)", connection.ErrFatal, err)
				return
			case errors.Is(err, mpath.ErrUnknownSession):
				if ctx.Err() == nil {
					fullReconnect("server lost the mpath session")
				}
				return
			}
		} else if errors.Is(err, protocol.ErrTURNRejected) && ctx.Err() == nil {
			log.Warn("peer connection failed with TURN error, triggering full reconnect", "error", err)
			fullReconnect(err.Error())
			return
		}
		if ctx.Err() != nil {
			return
		}
		delay = nextPeerDelay(delay)
		log.Warn("peer dial failed", "delay", delay, "error", err)
	}
}

const (
	peerReconnectInit = 1 * time.Second  // initial peer redial delay
	peerReconnectMax  = 10 * time.Second // maximum peer redial delay
	peerStableAfter   = 10 * time.Second // online time after which a drop is redialed at once
)

func nextPeerDelay(d time.Duration) time.Duration {
	if d == 0 {
		return peerReconnectInit
	}
	return min(d*2, peerReconnectMax)
}

// mpathClientAuth sends the client config on the auth stream and returns the session UUID
func mpathClientAuth(ctx context.Context, mux *mpath.Mux, cfg *ClientConfig) (string, error) {
	st, err := mux.OpenStream(mpathAuthRoute)
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	cfgJSON, err := cfg.ToJSON(false, true)
	if err != nil {
		return "", err
	}
	hello := make([]byte, 0, 5+len(cfgJSON))
	hello = append(hello, relayHandshakeVersion)
	hello = binary.BigEndian.AppendUint32(hello, uint32(len(cfgJSON)))
	hello = append(hello, cfgJSON...)
	if _, err := st.Write(hello); err != nil {
		return "", fmt.Errorf("write auth: %w", err)
	}
	ack, err := readFramed(st, 4096)
	if err != nil {
		return "", fmt.Errorf("read auth ack: %w", err)
	}
	id, errMsg, err := parsePrimaryAck(ack)
	if err != nil {
		return "", err
	}
	if errMsg != "" {
		return "", &ErrAckRejected{msg: errMsg}
	}
	return uuid.UUID(id).String(), nil
}

// readFramed reads a u32 length-prefixed message
func readFramed(r io.Reader, maxLen int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > maxLen {
		return nil, fmt.Errorf("message too large: %d", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// framedWriter adapts writePrimaryAck's single Write into a length-prefixed message
type framedWriter struct{ w io.Writer }

func (f framedWriter) Write(b []byte) (int, error) {
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	if _, err := f.w.Write(append(buf, b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

// openMpathChannel opens a stream or datagram flow for a route
func (st *mpathClientState) openChannel(routeIdx byte) (net.Conn, error) {
	if int(routeIdx) >= len(st.cfg.Routes) {
		return nil, fmt.Errorf("relay: invalid route index %d", routeIdx)
	}
	if st.cfg.Routes[routeIdx].Socket == "udp" {
		return st.mux.OpenDatagramFlow(routeIdx), nil
	}
	return st.mux.OpenStream(routeIdx)
}

// sessionAddr names a multipath session in place of a single peer address
type sessionAddr string

func (a sessionAddr) Network() string { return "mpath" }
func (a sessionAddr) String() string  { return string(a) }

// isMpathPacket reports whether the first packet of a peer conn starts an mpath handshake
func isMpathPacket(b []byte) bool {
	return len(b) > 0 && (b[0] == 0xA1 || b[0] == 0xA3)
}

// peekedConn replays an already-read first packet
type peekedConn struct {
	net.Conn
	first []byte
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if c.first != nil {
		n := copy(b, c.first)
		c.first = nil
		return n, nil
	}
	return c.Conn.Read(b)
}

// dispatchPeer reads the first packet of a new peer conn and routes it to mpath or the legacy handshake
func (D *Handler) dispatchPeer(ctx context.Context, client protocol.ServerClient, serverCfg *ServerConfig, out chan<- connection.ServerClient) error {
	_ = client.Conn.SetReadDeadline(time.Now().Add(relayHandshakeTimeout))
	buf := make([]byte, 65536)
	n, err := client.Conn.Read(buf)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("read first packet: %w", err)
	}
	_ = client.Conn.SetReadDeadline(time.Time{})
	client.Conn = &peekedConn{Conn: client.Conn, first: append([]byte(nil), buf[:n]...)}
	if isMpathPacket(buf[:n]) {
		return D.mpathServer.HandleConn(ctx, client.Conn)
	}
	return D.handleIncomingPeer(ctx, client, serverCfg, out)
}

// serveMpathSessions authenticates accepted sessions and emits their channels
func (D *Handler) serveMpathSessions(ctx context.Context, out chan<- connection.ServerClient) {
	for {
		select {
		case <-ctx.Done():
			return
		case sess := <-D.mpathServer.Accept():
			go func() {
				if err := D.serveMpathSession(ctx, sess, out); err != nil {
					D.log.Warn("relay mpath session failed", "error", err)
				}
			}()
		}
	}
}

func (D *Handler) serveMpathSession(ctx context.Context, sess *mpath.Session, out chan<- connection.ServerClient) error {
	mux, err := mpath.NewServerMux(sess)
	if err != nil {
		_ = sess.Close()
		return err
	}
	defer func() { _ = mux.Close() }()
	D.mpathSessions.Store(mux, struct{}{})
	defer D.mpathSessions.Delete(mux)
	sess.SetPathHandlers(nil, nil)

	authCtx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout*3)
	auth, err := mux.AcceptStream(authCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("wait auth stream: %w", err)
	}
	if auth.Route != mpathAuthRoute {
		return errors.New("first stream is not the auth stream")
	}
	_ = auth.SetDeadline(time.Now().Add(relayHandshakeTimeout))
	var hdr [5]byte
	if _, err := io.ReadFull(auth, hdr[:]); err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	if hdr[0] != relayHandshakeVersion {
		_ = writePrimaryAck(framedWriter{auth}, [16]byte{}, fmt.Sprintf("unsupported handshake version %d", hdr[0]))
		return fmt.Errorf("unsupported handshake version %d", hdr[0])
	}
	size := binary.BigEndian.Uint32(hdr[1:])
	if size == 0 || size > 256*1024 {
		return errors.New("bad auth size")
	}
	cfgJSON := make([]byte, size)
	if _, err := io.ReadFull(auth, cfgJSON); err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	clientCfg, user, routes, err := D.validateClientConfig(cfgJSON)
	if err != nil {
		_ = writePrimaryAck(framedWriter{auth}, [16]byte{}, err.Error())
		time.Sleep(time.Second) // let the rejection reach the client
		return err
	}
	sessionUUID := uuid.New()
	if err := writePrimaryAck(framedWriter{auth}, sessionUUID, ""); err != nil {
		return err
	}
	_ = auth.Close()

	sid := sessionUUID.String()
	addr := sessionAddr("mpath/" + sid)
	D.log.Info("relay mpath session started", "session_uuid", sid, "user_uuid", clientCfg.UserUUID, "routes", len(routes))
	defer D.log.Info("relay mpath session ended", "session_uuid", sid, "reason", sess.Err())

	emit := func(conn net.Conn, routeIdx byte, wantSocket string, flowID string) {
		if int(routeIdx) >= len(routes) || routes[routeIdx].Socket != wantSocket {
			D.log.Warn("client opened an invalid channel", "session_uuid", sid, "route_idx", routeIdx, "socket", wantSocket)
			_ = conn.Close()
			return
		}
		select {
		case out <- connection.ServerClient{Address: addr, Conn: conn, User: user, Routes: routes, RouteIdx: routeIdx, SessionUUID: sid + ":" + flowID}:
		case <-ctx.Done():
			_ = conn.Close()
		}
	}

	go func() {
		for {
			f, err := mux.AcceptDatagramFlow(ctx)
			if err != nil {
				return
			}
			emit(f, f.Route, "udp", fmt.Sprintf("d%d", f.ID()))
		}
	}()
	for {
		st, err := mux.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		emit(st, st.Route, "tcp", fmt.Sprint(st.ID()))
	}
}
