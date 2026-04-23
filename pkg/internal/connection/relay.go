package connection

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	platformpkg "github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
	transportpkg "github.com/theairblow/turnable/pkg/internal/transport"
)

const (
	relayHandshakeVersion byte = 2

	relayHelloTypePrimary   byte = 1
	relayHelloTypeSecondary byte = 2

	relayAckOK  byte = 0
	relayAckErr byte = 1

	relayHandshakeTimeout = 10 * time.Second

	fullReconnectInit = 5 * time.Second
	fullReconnectMax  = 30 * time.Second
)

// ErrAckRejected is returned when the server sends an error ACK during handshake
type ErrAckRejected struct{ msg string }

func (e *ErrAckRejected) Error() string { return e.msg }

// RelayHandler represent a relay connection handler
type RelayHandler struct {
	running atomic.Bool

	// server-side
	serverConfig *config.ServerConfig
	proto        protocol.Handler
	sessions     sync.Map

	// client-side
	platform  platformpkg.Handler
	muxClient *TinyMuxClient
	peerConn  *PeerConn
	cancel    context.CancelFunc

	clientConfig    *config.ClientConfig
	sessionUUID     string
	reconnecting    atomic.Bool
	reconnectMu     sync.Mutex
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc
}

// relayServerSession tracks a multi-peer server-side session
type relayServerSession struct {
	peerConn  *PeerConn
	muxServer atomic.Pointer[TinyMuxServer]
	userUUID  string
	routeID   string
	fullEnc   bool
}

// ID returns the unique ID of this handler
func (D *RelayHandler) ID() string {
	return "relay"
}

// Start starts the server listener
func (D *RelayHandler) Start(cfg config.ServerConfig) error {
	if !D.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	if !cfg.Relay.Enabled {
		return errors.New("relay mode is not enabled on the server")
	}
	if common.IsNullOrWhiteSpace(cfg.Relay.PublicIP) {
		return errors.New("relay mode requires public_ip")
	}
	if cfg.Relay.Port == nil {
		return errors.New("relay mode requires port")
	}
	if !protocol.HandlerExists(cfg.Relay.Proto) {
		return fmt.Errorf("invalid relay protocol: %s", cfg.Relay.Proto)
	}

	handler, err := protocol.GetHandler(cfg.Relay.Proto)
	if err != nil {
		return err
	}
	if err := handler.Start(cfg); err != nil {
		return err
	}

	D.serverConfig = &cfg
	D.proto = handler
	success = true
	return nil
}

// Stop stops the relay-side protocol listener.
func (D *RelayHandler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	protoHandler := D.proto
	D.serverConfig = nil
	D.proto = nil

	if protoHandler == nil {
		return nil
	}

	D.sessions.Range(func(_, val any) bool {
		sess := val.(*relayServerSession)
		if ms := sess.muxServer.Load(); ms != nil {
			_ = ms.Disconnect()
		}
		return true
	})

	time.Sleep(100 * time.Millisecond)

	return protoHandler.Stop()
}

// Connect connects to a remote server
func (D *RelayHandler) Connect(cfg config.ClientConfig) error {
	if !D.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	if cfg.Type != D.ID() {
		return fmt.Errorf("invalid connection type %q, expected %q", cfg.Type, D.ID())
	}
	if common.IsNullOrWhiteSpace(cfg.Gateway) {
		return errors.New("no gateway address was provided")
	}

	if cfg.Proto == "none" {
		slog.Warn("using no protocol is dangerous, please reconsider!")
	}

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())

	D.clientConfig = &cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel

	if err := D.connectClientSession(); err != nil {
		reconnectCancel()
		return err
	}

	success = true
	return nil
}

// OpenChannel opens a new logical data channel
func (D *RelayHandler) OpenChannel() (net.Conn, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.reconnecting.Load() {
		return nil, ErrReconnecting
	}

	muxClient := D.muxClient

	if muxClient == nil {
		return nil, errors.New("relay: no active mux connection")
	}

	stream, err := muxClient.OpenChannel()
	if err != nil {
		if D.muxClient == muxClient {
			D.muxClient = nil
		}

		_ = muxClient.Close()
		return nil, fmt.Errorf("relay: mux channel open failed: %w", err)
	}

	cfg := D.clientConfig
	if cfg == nil {
		_ = stream.Close()
		return nil, errors.New("relay: no client config")
	}

	handler, err := transportpkg.GetHandler(cfg.Transport)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport setup: %w", err)
	}

	wrapped, err := handler.WrapClient(stream)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport wrap: %w", err)
	}

	return wrapped, nil
}

// Disconnect gracefully disconnects from the current remote server
func (D *RelayHandler) Disconnect() error {
	if !D.running.CompareAndSwap(true, false) {
		return nil
	}

	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""

	if cancel != nil {
		cancel()
	}

	if reconnectCancel != nil {
		reconnectCancel()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			_ = muxClient.Disconnect()
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Disconnect()
		}(),
	)
}

// Close forcibly closes the current remove server connection
func (D *RelayHandler) Close() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""

	if cancel != nil {
		cancel()
	}

	if reconnectCancel != nil {
		reconnectCancel()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Close()
		}(),
	)
}

// connectClientSession establishes the platform, underlay, and tinymux session for the client.
func (D *RelayHandler) connectClientSession() error {
	D.reconnectMu.Lock()
	defer D.reconnectMu.Unlock()

	if D.cancel != nil {
		D.cancel()
		D.cancel = nil
	}
	if D.muxClient != nil {
		_ = D.muxClient.Disconnect()
		_ = D.muxClient.Close()
		D.muxClient = nil
	}
	if D.peerConn != nil {
		_ = D.peerConn.Close()
		D.peerConn = nil
	}
	if D.platform != nil {
		_ = D.platform.Close()
		D.platform = nil
	}

	cfg := D.clientConfig
	reconnectCtx := D.reconnectCtx

	if cfg == nil {
		return errors.New("relay reconnect requires client config")
	}
	if reconnectCtx == nil {
		return errors.New("relay reconnect context is not initialized")
	}

	platformHandler, err := platformpkg.GetHandler(cfg.PlatformID)
	if err != nil {
		return err
	}
	if err := platformHandler.Authorize(cfg.CallID, cfg.Username, cfg.Interactive); err != nil {
		return err
	}

	if os.Getenv("QUIT_AFTER_AUTH") == "1" {
		slog.Info("QUIT_AFTER_AUTH set, quitting...")
		os.Exit(0)
	}

	sessionCtx, sessionCancel := context.WithCancel(reconnectCtx)
	events := platformHandler.WatchEvents(sessionCtx)

	if err := platformHandler.Connect(); err != nil {
		sessionCancel()
		_ = platformHandler.Close()
		return err
	}

	if !protocol.HandlerExists(cfg.Proto) {
		sessionCancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("protocol handler %s not found", cfg.Proto)
	}

	turnInfo := platformHandler.GetTURNInfo()
	dest, err := net.ResolveUDPAddr("udp", cfg.Gateway)
	if err != nil {
		sessionCancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("invalid relay gateway %q: %w", cfg.Gateway, err)
	}

	relayInfo := protocol.RelayInfo{
		Address:   turnInfo.Address,
		Addresses: append([]string(nil), turnInfo.Addresses...),
		Username:  turnInfo.Username,
		Password:  turnInfo.Password,
	}

	go watchPlatform(sessionCtx, events)

	numPeers := cfg.Peers
	if numPeers < 1 {
		numPeers = 1
	}

	fullReconnect := func(reason string) {
		if !D.reconnecting.CompareAndSwap(false, true) {
			return
		}

		go func() {
			defer D.reconnecting.Store(false)
			delay := fullReconnectInit

			slog.Info("starting full reconnect", "reason", reason, "delay", delay)
			select {
			case <-sessionCtx.Done():
				return
			case <-time.After(delay):
			}

			for {
				if err := D.connectClientSession(); err == nil {
					return
				} else {
					slog.Warn("full reconnect failed, retrying", "delay", delay, "error", err)
				}

				ctx := D.reconnectCtx
				if ctx == nil {
					return
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}

				delay = min(delay*2, fullReconnectMax)
			}
		}()
	}

	type connPair struct {
		raw, enc net.Conn
		idx      int
	}

	connCh := make(chan connPair, numPeers)

	connectAndEncrypt := func(idx int, ctx context.Context) (raw, enc net.Conn, err error) {
		h, _ := protocol.GetHandler(cfg.Proto)
		h.SetLogger(slog.With("peer_idx", idx))

		connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
		defer connCancel()

		raw, err = h.Connect(connCtx, dest, relayInfo, true)
		if err != nil {
			return
		}

		_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))

		enc, err = wrapClientEncryptedConn(raw, cfg.PubKey)
		if err != nil {
			_ = raw.Close()
			raw = nil
			return
		}

		_ = raw.SetDeadline(time.Time{})

		return
	}

	var spawnPeer func(idx int)
	spawnPeer = func(idx int) {
		go func() {
			delay := peerReconnectInit
			for {
				raw, enc, err := connectAndEncrypt(idx, sessionCtx)
				if err != nil {
					if sessionCtx.Err() != nil {
						return
					}
					if errors.Is(err, protocol.ErrQuotaReached) {
						slog.Warn("peer quota reached, backing off", "peer_idx", idx, "delay", peerQuotaBackoff)
						delay = peerQuotaBackoff
					}

					slog.Warn("peer connect failed", "peer_idx", idx, "error", err, "delay", delay)
					select {
					case <-sessionCtx.Done():
						return
					case <-time.After(delay):
					}

					delay = min(delay*2, peerReconnectMax)
					continue
				}

				select {
				case connCh <- connPair{raw, enc, idx}:
					return
				case <-sessionCtx.Done():
					_ = raw.Close()
					return
				}
			}
		}()
	}

	for i := 0; i < numPeers; i++ {
		spawnPeer(i)
	}

	pickConn := func(p connPair) net.Conn {
		if cfg.Encryption == "full" {
			return p.enc
		}
		return p.raw
	}

	var assignedUUID [16]byte
	makePeerReconnectFn := func(idx int) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			raw, enc, err := connectAndEncrypt(idx, ctx)
			if err != nil {
				return nil, err
			}

			_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			err = doClientSecondaryHandshake(enc, assignedUUID, cfg.UserUUID, cfg.RouteID)
			_ = raw.SetDeadline(time.Time{})

			if err != nil {
				_ = raw.Close()
				var ackErr *ErrAckRejected
				if errors.As(err, &ackErr) {
					fullReconnect(err.Error())
					return nil, ErrPeerDone
				}
				return nil, err
			}
			return pickConn(connPair{raw, enc, idx}), nil
		}
	}

	var peerConn *PeerConn
	var muxClient *TinyMuxClient
primaryLoop:
	for {
		select {
		case <-sessionCtx.Done():
			sessionCancel()
			_ = platformHandler.Disconnect()
			return sessionCtx.Err()
		case p := <-connCh:

			_ = p.raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			cfgJson, err := cfg.ToJSON(true)
			if err != nil {
				_ = p.raw.Close()
				slog.Warn("primary handshake failed, retrying", "peer_idx", p.idx, "error", err)
				spawnPeer(p.idx)
				continue
			}

			uuidBytes, hErr := doClientPrimaryHandshake(p.enc, cfgJson)
			_ = p.raw.SetDeadline(time.Time{})
			if hErr != nil {
				_ = p.raw.Close()
				var ackErr *ErrAckRejected
				if errors.As(hErr, &ackErr) {
					sessionCancel()
					_ = platformHandler.Disconnect()
					return hErr
				}
				slog.Warn("primary handshake failed, retrying", "peer_idx", p.idx, "error", hErr)
				spawnPeer(p.idx)
				continue
			}

			assignedUUID = uuidBytes
			peerConn = NewPeerConn(sessionCtx)
			peerConn.SetLogger(slog.With("session_uuid", uuid.UUID(uuidBytes).String()))
			peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

			if addErr := peerConn.AddPeer(pickConn(p), makePeerReconnectFn(p.idx)); addErr != nil {
				_ = p.raw.Close()
				_ = peerConn.Close()
				spawnPeer(p.idx)
				continue
			}

			var mErr error
			muxClient, mErr = NewTinyMuxClient(sessionCtx, peerConn)
			if mErr != nil {
				_ = peerConn.Close()
				spawnPeer(p.idx)
				continue
			}

			platCfg := platformHandler.GetConfig()
			if platCfg.BandwidthRelay > 0 {
				muxClient.SetRateLimit(platCfg.BandwidthRelay * float64(numPeers))
			}

			break primaryLoop
		}
	}

	go func() {
		select {
		case <-muxClient.Done():
			fullReconnect("tinymux session died")
		case <-sessionCtx.Done():
		}
	}()

	sessionUUIDStr := uuid.UUID(assignedUUID).String()
	D.cancel = sessionCancel
	D.platform = platformHandler
	D.muxClient = muxClient
	D.peerConn = peerConn
	D.sessionUUID = sessionUUIDStr

	slog.Info("relay client session connected", "session_uuid", sessionUUIDStr, "peers", numPeers)

	go func() {
		for i := 0; i < numPeers-1; i++ {
			select {
			case <-sessionCtx.Done():
				return
			case p := <-connCh:
				go func(p connPair) {
					_ = p.raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
					sErr := doClientSecondaryHandshake(p.enc, assignedUUID, cfg.UserUUID, cfg.RouteID)
					_ = p.raw.SetDeadline(time.Time{})
					if sErr != nil {
						_ = p.raw.Close()
						var ackErr *ErrAckRejected
						if errors.As(sErr, &ackErr) {
							fullReconnect(sErr.Error())
							return
						}
						slog.Warn("secondary handshake failed, retrying", "peer_idx", p.idx, "error", sErr)
						spawnPeer(p.idx)
						return
					}

					if addErr := peerConn.AddPeer(pickConn(p), makePeerReconnectFn(p.idx)); addErr != nil {
						slog.Warn("peer add failed", "peer_idx", p.idx, "error", addErr)
						_ = p.raw.Close()
					}
				}(p)
			}
		}
	}()

	return nil
}

// AcceptClients accepts and emits new authenticated server clients
func (D *RelayHandler) AcceptClients(ctx context.Context) (<-chan ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}

	out := make(chan ServerClient)
	protoHandler := D.proto
	serverCfg := D.serverConfig

	go func() {
		defer close(out)

		if protoHandler == nil || serverCfg == nil {
			return
		}

		clientCh, err := protoHandler.AcceptClients(ctx)
		if err != nil {
			slog.Warn("accept clients failed", "error", err)
			return
		}

		for client := range clientCh {
			go func() {
				if err := D.handleIncomingPeer(ctx, client, serverCfg, out); err != nil {
					slog.Warn("relay peer handling failed", "addr", client.Address, "error", err)
				}
			}()
		}
	}()

	return out, nil
}

// handleIncomingPeer dispatches an incoming peer to the primary or secondary handler
func (D *RelayHandler) handleIncomingPeer(
	ctx context.Context,
	client protocol.ServerClient,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	_ = client.Conn.SetDeadline(time.Now().Add(relayHandshakeTimeout))

	// TODO: fix potential memory leak
	encConn, err := wrapServerEncryptedConn(client.Conn, serverCfg.PrivKey)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("peer encryption setup: %w", err)
	}

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := encConn.Write(challenge[:]); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write challenge: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := encConn.Read(buf)
	if err != nil {
		_ = encConn.Close()
		return fmt.Errorf("read hello: %w", err)
	}
	if n < 9 {
		_ = encConn.Close()
		return errors.New("hello packet too short")
	}

	if [8]byte(buf[1:9]) != challenge {
		_ = encConn.Close()
		return errors.New("challenge mismatch: possible replay")
	}

	switch buf[0] {
	case relayHelloTypePrimary:
		return D.handlePrimaryPeer(ctx, client, encConn, buf[9:n], serverCfg, out)
	case relayHelloTypeSecondary:
		return D.handleSecondaryPeer(client, encConn, buf[9:n])
	default:
		_ = encConn.Close()
		return fmt.Errorf("unknown hello type %d", buf[0])
	}
}

// handlePrimaryPeer handles a primary peer connection
func (D *RelayHandler) handlePrimaryPeer(
	ctx context.Context,
	client protocol.ServerClient,
	encConn *EncryptedConn,
	helloPayload []byte,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	configJSON, err := parsePrimaryHello(helloPayload)
	if err != nil {
		_ = writePrimaryAck(encConn, [16]byte{}, err.Error())
		_ = encConn.Close()
		return fmt.Errorf("parse primary hello: %w", err)
	}

	clientCfg, user, route, err := validateClientConfig(*serverCfg, configJSON)
	if err != nil {
		_ = writePrimaryAck(encConn, [16]byte{}, err.Error())
		_ = encConn.Close()
		return err
	}

	sessionUUID := uuid.New()
	var sessionUUIDBin [16]byte
	copy(sessionUUIDBin[:], sessionUUID[:])

	if err := writePrimaryAck(encConn, sessionUUIDBin, ""); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write primary ack: %w", err)
	}

	_ = encConn.SetDeadline(time.Time{})

	sessionUUIDStr := sessionUUID.String()
	slog.Info("relay handshake started", "addr", client.Address)

	peerConn := NewPeerConn(ctx)
	peerConn.SetLogger(slog.With("session_uuid", sessionUUIDStr))
	newSess := &relayServerSession{
		peerConn: peerConn,
		userUUID: clientCfg.UserUUID,
		routeID:  clientCfg.RouteID,
		fullEnc:  clientCfg.Encryption == "full",
	}

	actual, loaded := D.sessions.LoadOrStore(sessionUUIDStr, newSess)
	if loaded {
		existSess := actual.(*relayServerSession)
		var conn net.Conn
		if existSess.fullEnc {
			conn = encConn
		} else {
			conn = client.Conn
		}
		_ = existSess.peerConn.AddPeer(conn, nil)
		return nil
	}

	defer D.sessions.Delete(sessionUUIDStr)

	var peer0 net.Conn
	if clientCfg.Encryption == "full" {
		peer0 = encConn
	} else {
		peer0 = client.Conn
	}

	_ = peerConn.AddPeer(peer0, nil)

	muxServer, err := NewTinyMuxServer(peerConn)
	if err != nil {
		_ = peerConn.Close()
		return fmt.Errorf("tinymux setup: %w", err)
	}

	defer func() { _ = muxServer.Close() }()
	newSess.muxServer.Store(muxServer)

	if route.BandwidthRelay > 0 {
		muxServer.SetRateLimit(route.BandwidthRelay * float64(clientCfg.Peers))
	}

	peerConn.SetOnAllPeersGone(func() { _ = muxServer.Close() })

	transportHandler, transportErr := transportpkg.GetHandler(route.Transport)
	if transportErr != nil {
		return fmt.Errorf("transport setup: %w", transportErr)
	}

	slog.Info("relay handshake completed", "addr", client.Address, "session_uuid", sessionUUIDStr, "user_uuid", clientCfg.UserUUID, "route_id", clientCfg.RouteID)

	for channel := range muxServer.AcceptChannels(ctx) {
		conn, wrapErr := transportHandler.WrapServer(channel.Conn)
		if wrapErr != nil {
			slog.Warn("transport wrap failed", "flow_id", channel.FlowID, "error", wrapErr)
			_ = channel.Conn.Close()
			continue
		}

		select {
		case out <- ServerClient{
			Address:     client.Address,
			Conn:        conn,
			Config:      clientCfg,
			User:        user,
			Route:       route,
			SessionUUID: fmt.Sprintf("%s:%d", sessionUUIDStr, channel.FlowID),
		}:
		case <-ctx.Done():
			_ = channel.Conn.Close()
			return nil
		}
	}

	select {
	case <-ctx.Done():
		_ = muxServer.Disconnect()
	default:
	}

	return nil
}

// handleSecondaryPeer handles a secondary peer connection
func (D *RelayHandler) handleSecondaryPeer(
	client protocol.ServerClient,
	encConn *EncryptedConn,
	helloPayload []byte,
) error {
	sessionUUIDBin, userUUID, routeID, err := parseSecondaryHello(helloPayload)
	if err != nil {
		_ = encConn.Close()
		return fmt.Errorf("parse secondary hello: %w", err)
	}

	sessionUUIDStr := uuid.UUID(sessionUUIDBin).String()

	existing, loaded := D.sessions.Load(sessionUUIDStr)
	if !loaded {
		_ = writeSecondaryAck(encConn, "session not found")
		_ = encConn.Close()
		return fmt.Errorf("secondary peer: session %s not found", sessionUUIDStr)
	}

	sess := existing.(*relayServerSession)

	if sess.userUUID != userUUID || sess.routeID != routeID {
		_ = writeSecondaryAck(encConn, "session not found")
		_ = encConn.Close()
		return fmt.Errorf("secondary peer: session mismatch for %s", sessionUUIDStr)
	}

	if err := writeSecondaryAck(encConn, ""); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write secondary ack: %w", err)
	}

	_ = encConn.SetDeadline(time.Time{})

	var conn net.Conn
	if sess.fullEnc {
		conn = encConn
	} else {
		conn = client.Conn
	}

	if err := sess.peerConn.AddPeer(conn, nil); err != nil {
		_ = encConn.Close()
		return err
	}

	return nil
}

// watchPlatform watches platform signaling events
func watchPlatform(ctx context.Context, events <-chan platformpkg.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				slog.Debug("relay signaling monitor stopped: event stream closed")
				return
			}
			if event.Type == platformpkg.EventCallEnded {
				slog.Debug("relay signaling reported call ended", "metadata", event.Metadata)
			}
		}
	}
}

// validateClientConfig parses the client config JSON, validates it and authorizes access to the requested route.
func validateClientConfig(serverCfg config.ServerConfig, configJSON string) (*config.ClientConfig, *config.User, *config.Route, error) {
	clientCfg, err := config.NewClientConfigFromJSON(configJSON)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse client config json: %w", err)
	}

	if common.IsNullOrWhiteSpace(clientCfg.UserUUID) {
		return nil, nil, nil, errors.New("relay handshake missing user_uuid")
	}
	if common.IsNullOrWhiteSpace(clientCfg.RouteID) {
		return nil, nil, nil, errors.New("relay handshake missing route_id")
	}
	if clientCfg.Type != "relay" {
		return nil, nil, nil, fmt.Errorf("unexpected connection type %q", clientCfg.Type)
	}

	switch clientCfg.Encryption {
	case "handshake", "full":
	default:
		return nil, nil, nil, fmt.Errorf("invalid relay encryption mode %q", clientCfg.Encryption)
	}

	user, err := serverCfg.GetUser(clientCfg.UserUUID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve user: %w", err)
	}

	route, err := serverCfg.GetRoute(clientCfg.RouteID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve route: %w", err)
	}

	isAllowed := false
	for _, routeID := range user.AllowedRoutes {
		if routeID == route.ID {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		return nil, nil, nil, fmt.Errorf("user %s is not authorized for route %s", user.UUID, route.ID)
	}

	if clientCfg.Socket != route.Socket {
		return nil, nil, nil, fmt.Errorf("expected socket type %s, got %s", route.Socket, clientCfg.Socket)
	}

	return clientCfg, user, route, nil
}

// writePrimaryHello sends a primary handshake hello packet
func writePrimaryHello(w io.Writer, challenge [8]byte, configJSON string) error {
	configBytes := []byte(configJSON)
	buf := make([]byte, 0, 1+8+1+4+len(configBytes))
	buf = append(buf, relayHelloTypePrimary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(configBytes)))
	buf = append(buf, configBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryHello parses a primary handshake hello packet
func parsePrimaryHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("primary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported primary hello version %d", data[0])
	}
	configLen := binary.BigEndian.Uint32(data[1:5])
	if configLen == 0 {
		return "", errors.New("primary hello: empty config JSON")
	}
	if len(data) < 5+int(configLen) {
		return "", errors.New("primary hello: truncated config")
	}
	return string(data[5 : 5+configLen]), nil
}

// writeSecondaryHello sends a secondary handshake hello packet
func writeSecondaryHello(w io.Writer, challenge [8]byte, sessionUUID [16]byte, userUUID, routeID string) error {
	userBytes := []byte(userUUID)
	routeBytes := []byte(routeID)
	buf := make([]byte, 0, 1+8+1+16+2+len(userBytes)+2+len(routeBytes))
	buf = append(buf, relayHelloTypeSecondary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = append(buf, sessionUUID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(userBytes)))
	buf = append(buf, userBytes...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(routeBytes)))
	buf = append(buf, routeBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryHello parses a secondary handshake hello packet
func parseSecondaryHello(data []byte) ([16]byte, string, string, error) {
	if len(data) < 19 { // version(1) + uuid(16) + userLen(2)
		return [16]byte{}, "", "", errors.New("secondary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", "", fmt.Errorf("unsupported secondary hello version %d", data[0])
	}
	var sessionUUID [16]byte
	copy(sessionUUID[:], data[1:17])
	userLen := binary.BigEndian.Uint16(data[17:19])
	off := 19
	if len(data) < off+int(userLen)+2 {
		return [16]byte{}, "", "", errors.New("secondary hello: truncated user uuid")
	}
	userUUID := string(data[off : off+int(userLen)])
	off += int(userLen)
	routeLen := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if len(data) < off+int(routeLen) {
		return [16]byte{}, "", "", errors.New("secondary hello: truncated route id")
	}
	routeID := string(data[off : off+int(routeLen)])
	return sessionUUID, userUUID, routeID, nil
}

// writePrimaryAck sends a primary handshake ack packet
func writePrimaryAck(w io.Writer, sessionUUID [16]byte, errMsg string) error {
	if errMsg == "" {
		buf := make([]byte, 0, 1+1+16)
		buf = append(buf, relayHandshakeVersion, relayAckOK)
		buf = append(buf, sessionUUID[:]...)
		_, err := w.Write(buf)
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryAck parses a primary handshake ack packet
func parsePrimaryAck(data []byte) ([16]byte, string, error) {
	if len(data) < 2 {
		return [16]byte{}, "", errors.New("primary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", fmt.Errorf("unsupported primary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		if len(data) < 18 {
			return [16]byte{}, "", errors.New("primary ack uuid too short")
		}
		var sessionUUID [16]byte
		copy(sessionUUID[:], data[2:18])
		return sessionUUID, "", nil
	}
	if len(data) < 4 {
		return [16]byte{}, "", errors.New("primary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return [16]byte{}, "", errors.New("primary ack error truncated")
	}
	return [16]byte{}, string(data[4 : 4+errLen]), nil
}

// writeSecondaryAck sends a secondary handshake packet
func writeSecondaryAck(w io.Writer, errMsg string) error {
	if errMsg == "" {
		_, err := w.Write([]byte{relayHandshakeVersion, relayAckOK})
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryAck parses a secondary handshake ack packet
func parseSecondaryAck(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("secondary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported secondary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		return "", nil
	}
	if len(data) < 4 {
		return "", errors.New("secondary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return "", errors.New("secondary ack error truncated")
	}
	return string(data[4 : 4+errLen]), nil
}

// doClientPrimaryHandshake performs the full client primary handshake
func doClientPrimaryHandshake(conn net.Conn, configJSON string) ([16]byte, error) {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return [16]byte{}, fmt.Errorf("read challenge: %w", err)
	}
	if err := writePrimaryHello(conn, challenge, configJSON); err != nil {
		return [16]byte{}, fmt.Errorf("write primary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return [16]byte{}, fmt.Errorf("read primary ack: %w", err)
	}
	sessionUUID, errMsg, err := parsePrimaryAck(buf[:n])
	if err != nil {
		return [16]byte{}, err
	}
	if errMsg != "" {
		return [16]byte{}, &ErrAckRejected{msg: errMsg}
	}
	return sessionUUID, nil
}

// doClientSecondaryHandshake performs the full client secondary handshake
func doClientSecondaryHandshake(conn net.Conn, sessionUUID [16]byte, userUUID, routeID string) error {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if err := writeSecondaryHello(conn, challenge, sessionUUID, userUUID, routeID); err != nil {
		return fmt.Errorf("write secondary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read secondary ack: %w", err)
	}
	errMsg, err := parseSecondaryAck(buf[:n])
	if err != nil {
		return err
	}
	if errMsg != "" {
		return &ErrAckRejected{msg: errMsg}
	}
	return nil
}
