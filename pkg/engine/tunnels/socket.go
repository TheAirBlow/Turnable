package tunnels

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/config"
)

// udpIdleTimeout is the duration of inactivity after which a UDP pseudo-connection is torn down.
const udpIdleTimeout = 60 * time.Second

// SocketHandler accepts local clients and dials remote routes for TCP and UDP sockets.
// LocalAddr is the only stateful field; all per-connection state lives in returned streams.
type SocketHandler struct {
	LocalAddr string
}

// ID returns the tunnel handler identifier.
func (S *SocketHandler) ID() string {
	return "socket"
}

// Open accepts local TCP or UDP clients and yields them as independent streams.
func (S *SocketHandler) Open(ctx context.Context, socketType string) (<-chan AcceptedClient, error) {
	switch strings.ToLower(socketType) {
	case "tcp":
		return S.acceptTCP(ctx)
	case "udp":
		return S.acceptUDP(ctx)
	default:
		return nil, fmt.Errorf("unsupported socket type %q", socketType)
	}
}

// Connect dials a remote TCP or UDP address from the route.
// The returned ReadWriteCloser wraps the raw socket directly; no internal goroutines are started.
func (S *SocketHandler) Connect(ctx context.Context, route *config.Route) (io.ReadWriteCloser, error) {
	socketType := strings.ToLower(route.Socket)
	address := net.JoinHostPort(route.Address, fmt.Sprintf("%d", route.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, socketType, address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s route: %w", socketType, err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return conn, nil
}

func (S *SocketHandler) acceptTCP(ctx context.Context) (<-chan AcceptedClient, error) {
	addr := S.LocalAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on tcp %s: %w", addr, err)
	}
	slog.Info("local tcp listener started", "addr", listener.Addr())

	accepted := make(chan AcceptedClient)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		defer close(accepted)
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || isClosedNetErr(err) {
					return
				}
				slog.Warn("tcp accept failed", "error", err)
				continue
			}
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case accepted <- AcceptedClient{Stream: conn, Close: conn.Close}:
			}
		}
	}()
	return accepted, nil
}

func (S *SocketHandler) acceptUDP(ctx context.Context) (<-chan AcceptedClient, error) {
	addr := S.LocalAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve udp addr %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on udp %s: %w", addr, err)
	}
	slog.Info("local udp listener started", "addr", conn.LocalAddr())

	a := &udpAcceptor{
		ctx:      ctx,
		conn:     conn,
		acceptCh: make(chan AcceptedClient),
		peers:    make(map[string]*udpPeerStream),
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go a.readLoop()
	return a.acceptCh, nil
}

// udpAcceptor multiplexes an inbound UDP listener into per-peer virtual connections.
type udpAcceptor struct {
	ctx      context.Context
	conn     *net.UDPConn
	acceptCh chan AcceptedClient

	mu    sync.Mutex
	peers map[string]*udpPeerStream
}

// readLoop reads datagrams and dispatches them to the per-peer stream.
func (a *udpAcceptor) readLoop() {
	defer close(a.acceptCh)
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			if a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) || isClosedNetErr(err) {
				return
			}
			slog.Warn("udp read failed", "error", err)
			continue
		}

		packet := append([]byte(nil), buf[:n]...)
		stream, isNew := a.getOrCreatePeer(addr)
		if !stream.deliver(packet) {
			continue
		}
		if !isNew {
			continue
		}

		select {
		case <-a.ctx.Done():
			_ = stream.Close()
			return
		case a.acceptCh <- AcceptedClient{Stream: stream, Close: stream.Close}:
		}
	}
}

// getOrCreatePeer returns the virtual stream for the given peer, creating it if necessary.
func (a *udpAcceptor) getOrCreatePeer(addr *net.UDPAddr) (*udpPeerStream, bool) {
	key := addr.String()
	a.mu.Lock()
	defer a.mu.Unlock()

	if s, ok := a.peers[key]; ok {
		return s, false
	}

	ctx, cancel := context.WithCancel(a.ctx)
	s := &udpPeerStream{
		ctx:    ctx,
		cancel: cancel,
		conn:   a.conn,
		parent: a,
		key:    key,
		peer:   addr,
		readCh: make(chan []byte, 64),
	}
	a.peers[key] = s
	return s, true
}

// removePeer removes and closes the virtual stream for the given peer.
func (a *udpAcceptor) removePeer(key string, s *udpPeerStream) {
	a.mu.Lock()
	if cur, ok := a.peers[key]; ok && cur == s {
		delete(a.peers, key)
	}
	a.mu.Unlock()
}

// udpPeerStream is a virtual stream representing one UDP peer.
// Read wraps ReadFromUDP with an idle timeout; Write wraps WriteToUDP directly.
type udpPeerStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   *net.UDPConn
	parent *udpAcceptor
	key    string
	peer   *net.UDPAddr
	readCh chan []byte
}

// Read returns the next datagram from this peer, or an idle-timeout error after udpIdleTimeout.
func (u *udpPeerStream) Read(p []byte) (int, error) {
	timer := time.NewTimer(udpIdleTimeout)
	defer timer.Stop()
	select {
	case <-u.ctx.Done():
		return 0, io.EOF
	case packet, ok := <-u.readCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, packet), nil
	case <-timer.C:
		return 0, &net.OpError{Op: "read", Net: "udp", Source: u.peer, Err: os.ErrDeadlineExceeded}
	}
}

// Write sends a datagram directly to the peer via the shared UDP socket.
func (u *udpPeerStream) Write(p []byte) (int, error) {
	if u.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return u.conn.WriteToUDP(p, u.peer)
}

// Close cancels this peer stream and removes it from the acceptor.
func (u *udpPeerStream) Close() error {
	u.cancel()
	u.parent.removePeer(u.key, u)
	return nil
}

// deliver writes a datagram into the peer stream's receive buffer.
func (u *udpPeerStream) deliver(packet []byte) bool {
	if u.ctx.Err() != nil {
		return false
	}
	select {
	case u.readCh <- packet:
	default:
	}
	return true
}

// isClosedNetErr reports whether the error indicates a closed network connection.
func isClosedNetErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") || strings.Contains(s, "already closed")
}
