package mpath

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	handshakeRetry   = 500 * time.Millisecond // handshake retransmission period
	handshakeTimeout = 15 * time.Second       // server wait for the first packet of a new conn
	attachMaxSkew    = 2 * time.Minute        // accepted clock skew for attach timestamps
	rejectLinger     = 2 * time.Second        // how long a rejected conn stays open so the reject arrives
)

// Client builds one session over paths added as peer connections come up
type Client struct {
	serverPub string
	cfg       Config

	mu      sync.Mutex
	hs      *clientHandshake
	sess    *Session
	hsBusy  bool
	hsDone  chan struct{}
	attachN int
}

// NewClient prepares a client session that authenticates the server by its public key
func NewClient(serverPub string, cfg Config) (*Client, error) {
	hs, err := newClientHandshake(serverPub)
	if err != nil {
		return nil, err
	}
	return &Client{serverPub: serverPub, cfg: cfg, hs: hs, hsDone: make(chan struct{})}, nil
}

// Session returns the established session, or nil before the first path completed the handshake
func (c *Client) Session() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// WaitSession blocks until the first handshake completes
func (c *Client) WaitSession(ctx context.Context) (*Session, error) {
	select {
	case <-c.hsDone:
		return c.Session(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// AddPath handshakes or attaches conn and adds it to the session. The session owns conn afterwards.
func (c *Client) AddPath(ctx context.Context, conn net.Conn) error {
	c.mu.Lock()
	if c.sess == nil && !c.hsBusy {
		c.hsBusy = true
		c.mu.Unlock()
		err := c.handshake(ctx, conn)
		c.mu.Lock()
		c.hsBusy = false
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()

	select {
	case <-c.hsDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	sess := c.Session()
	if sess.isClosed() {
		return ErrClosed
	}
	return c.attach(ctx, sess, conn)
}

// exchange sends req until a handshake reply arrives, returning the reply.
// A sealed data packet also counts: the server only sends those after binding the path.
func exchange(ctx context.Context, conn net.Conn, req []byte, accept func([]byte) (bool, error)) error {
	buf := make([]byte, 65536)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		if _, err := conn.Write(req); err != nil {
			return err
		}
		deadline := time.Now().Add(handshakeRetry)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return err
			}
			if n >= 3 && buf[0] == kindReject {
				if buf[2] == rejectVersion {
					return fmt.Errorf("%w: server speaks version %d, client %d", ErrVersion, buf[1], Version)
				}
				return ErrUnknownSession
			}
			if done, err := accept(buf[:n]); done || err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (c *Client) handshake(ctx context.Context, conn net.Conn) error {
	var k *keys
	err := exchange(ctx, conn, c.hs.hello, func(b []byte) (bool, error) {
		if b[0] != kindHelloAck {
			return false, nil
		}
		var err error
		k, err = c.hs.finish(b)
		return err == nil, err
	})
	if err != nil {
		return err
	}
	sess := newSession(&c.cfg, k, c.hs.sessionID, true)
	c.mu.Lock()
	c.sess = sess
	c.mu.Unlock()
	close(c.hsDone)
	sess.attach(conn)
	return nil
}

func (c *Client) attach(ctx context.Context, sess *Session, conn net.Conn) error {
	req := attachPacket(sess.id, sess.keys, time.Now())
	err := exchange(ctx, conn, req, func(b []byte) (bool, error) {
		if b[0] == kindAttachAck && len(b) == 1+sessionIDLen && string(b[1:]) == string(sess.id) {
			return true, nil
		}
		return b[0] == 0, nil
	})
	if err != nil {
		if errors.Is(err, ErrUnknownSession) {
			sess.closeWith(ErrUnknownSession, false)
		}
		return err
	}
	sess.attach(conn)
	return nil
}

// Server accepts sessions and binds incoming peer connections to them by session ID
type Server struct {
	key *ServerKey
	cfg Config

	mu       sync.Mutex
	sessions map[string]*serverSession
	accept   chan *Session
}

type serverSession struct {
	sess     *Session
	helloAck []byte
	attachID []byte
	seen     map[uint64]int64 // attach nonce -> unix time, for replay protection
}

// NewServer creates a server that decrypts handshakes with key
func NewServer(key *ServerKey, cfg Config) *Server {
	return &Server{key: key, cfg: cfg, sessions: make(map[string]*serverSession), accept: make(chan *Session, 16)}
}

// Accept returns newly established sessions
func (s *Server) Accept() <-chan *Session { return s.accept }

// Lookup returns a live session by ID
func (s *Server) Lookup(id []byte) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss := s.sessions[string(id)]; ss != nil {
		return ss.sess
	}
	return nil
}

// HandleConn reads the first packet of a new peer conn and binds it to a session.
// On success the session owns conn; on failure conn is closed.
func (s *Server) HandleConn(ctx context.Context, conn net.Conn) error {
	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if ctx.Err() != nil {
			_ = conn.Close()
			return ctx.Err()
		}
		pkt := buf[:n]
		if n == 0 {
			continue
		}
		switch pkt[0] {
		case kindHello:
			err = s.onHello(conn, pkt)
		case kindAttach:
			err = s.onAttach(conn, pkt)
		default:
			continue // stray data from a previous incarnation
		}
		if errors.Is(err, errRetry) {
			continue
		}
		if err != nil {
			if errors.Is(err, ErrVersion) || errors.Is(err, ErrUnknownSession) {
				// let the reject reach the client before tearing the conn down
				time.AfterFunc(rejectLinger, func() { _ = conn.Close() })
				return err
			}
			_ = conn.Close()
			return err
		}
		_ = conn.SetReadDeadline(time.Time{})
		return nil
	}
}

var errRetry = errors.New("retry")

func (s *Server) onHello(conn net.Conn, pkt []byte) error {
	if len(pkt) > 1+len(magic) && string(pkt[1:1+len(magic)]) == magic && pkt[1+len(magic)] != Version {
		_, _ = conn.Write(rejectPacket(rejectVersion))
		return ErrVersion
	}
	if len(pkt) >= 2+len(magic)+sessionIDLen {
		id := pkt[2+len(magic) : 2+len(magic)+sessionIDLen]
		s.mu.Lock()
		ss := s.sessions[string(id)]
		s.mu.Unlock()
		if ss != nil {
			// clients retry hellos on the conn already bound, so a hello for a known
			// session on a new conn is a replay: never bind it
			return errors.New("mpath: replayed hello")
		}
	}
	sid, k, ack, err := s.key.serverHello(pkt)
	if err != nil {
		return err
	}
	sess := newSession(&s.cfg, k, sid, false)
	ss := &serverSession{sess: sess, helloAck: ack, attachID: append([]byte{kindAttachAck}, sid...), seen: make(map[uint64]int64)}
	sess.handshakeReply = func(b []byte) []byte { return s.replyLate(ss, b) }
	s.mu.Lock()
	s.sessions[string(sid)] = ss
	s.mu.Unlock()
	go func() {
		<-sess.Done()
		s.mu.Lock()
		if s.sessions[string(sid)] == ss {
			delete(s.sessions, string(sid))
		}
		s.mu.Unlock()
	}()

	if _, err := conn.Write(ack); err != nil {
		sess.closeWith(err, false)
		return err
	}
	sess.attach(conn)
	select {
	case s.accept <- sess:
	default:
		go func() { s.accept <- sess }()
	}
	return nil
}

// verifyAttach checks an attach packet against its session and returns the session
func (s *Server) verifyAttach(pkt []byte) (*serverSession, error) {
	if len(pkt) < 1+sessionIDLen+sealOverhead {
		return nil, errors.New("mpath: malformed attach")
	}
	s.mu.Lock()
	ss := s.sessions[string(pkt[1:1+sessionIDLen])]
	s.mu.Unlock()
	if ss == nil {
		return nil, ErrUnknownSession
	}
	sealed := pkt[1+sessionIDLen:]
	plain, err := ss.sess.keys.recv.open(nil, sealed)
	if err != nil || len(plain) != 8 {
		return nil, errors.New("mpath: attach authentication failed")
	}
	ts := int64(binary.BigEndian.Uint64(plain))
	now := time.Now().Unix()
	if d := now - ts; d > int64(attachMaxSkew/time.Second) || d < -int64(attachMaxSkew/time.Second) {
		return nil, errors.New("mpath: stale attach")
	}
	nonce := binary.BigEndian.Uint64(sealed)
	ss.sess.mu.Lock()
	defer ss.sess.mu.Unlock()
	if _, dup := ss.seen[nonce]; dup {
		return ss, errRetry // a retransmission or replay; never binds a second conn
	}
	for k, t := range ss.seen {
		if now-t > 2*int64(attachMaxSkew/time.Second) {
			delete(ss.seen, k)
		}
	}
	ss.seen[nonce] = ts
	return ss, nil
}

func (s *Server) onAttach(conn net.Conn, pkt []byte) error {
	ss, err := s.verifyAttach(pkt)
	if errors.Is(err, ErrUnknownSession) {
		_, _ = conn.Write(rejectPacket(rejectUnknown))
		return err
	}
	if errors.Is(err, errRetry) {
		// the first copy bound a conn; if it was this conn the ack below is all it needs
		return errRetry
	}
	if err != nil {
		return err
	}
	if _, err := conn.Write(ss.attachID); err != nil {
		return err
	}
	ss.sess.attach(conn)
	return nil
}

// replyLate answers handshake retransmissions arriving on an already bound path
func (s *Server) replyLate(ss *serverSession, b []byte) []byte {
	switch b[0] {
	case kindHello:
		return ss.helloAck
	case kindAttach:
		return ss.attachID
	}
	return nil
}
