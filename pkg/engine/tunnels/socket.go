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

// udpIdleTimeout is the duration of inactivity after which a UDP connection is torn down
const udpIdleTimeout = 60 * time.Second

// SocketHandler accepts local clients and dials remote routes for TCP and UDP sockets
type SocketHandler struct {
	LocalAddr string
}

// ID returns the tunnel handler identifier.
func (S *SocketHandler) ID() string { return "socket" }

// Open accepts local TCP or UDP clients and yields them as independent streams
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

// Connect dials a remote TCP or UDP address from the route
func (S *SocketHandler) Connect(ctx context.Context, route *config.Route) (net.Conn, error) {
	address := net.JoinHostPort(route.Address, fmt.Sprintf("%d", route.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, strings.ToLower(route.Socket), address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s route: %w", route.Socket, err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return conn, nil
}

// acceptTCP starts a TCP listener and yields each accepted connection as a stream
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
	go func() { <-ctx.Done(); _ = listener.Close() }()
	go func() {
		defer close(accepted)
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				s := err.Error()
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) ||
					strings.Contains(s, "use of closed network connection") || strings.Contains(s, "already closed") {
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

// acceptUDP starts a UDP listener and yields each unique remote peer as a virtual stream
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

	var mu sync.Mutex
	peers := make(map[string]*udpPeerStream)
	acceptCh := make(chan AcceptedClient)

	go func() { <-ctx.Done(); _ = conn.Close() }()
	go func() {
		defer close(acceptCh)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				s := err.Error()
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) ||
					strings.Contains(s, "use of closed network connection") || strings.Contains(s, "already closed") {
					return
				}
				slog.Warn("udp read failed", "error", err)
				continue
			}

			packet := append([]byte(nil), buf[:n]...)
			key := addr.String()

			mu.Lock()
			peer, exists := peers[key]
			if !exists {
				pCtx, pCancel := context.WithCancel(ctx)
				p := &udpPeerStream{
					ctx:       pCtx,
					cancel:    pCancel,
					conn:      conn,
					peer:      addr,
					readCh:    make(chan []byte, 1024),
					idleTimer: time.NewTimer(udpIdleTimeout),
				}
				p.removeFn = func() {
					mu.Lock()
					if peers[key] == p {
						delete(peers, key)
					}
					mu.Unlock()
				}
				peers[key] = p
				peer = p
			}
			mu.Unlock()

			if !peer.deliver(packet) {
				continue
			}
			if exists {
				continue
			}

			select {
			case <-ctx.Done():
				peer.Close()
				return
			case acceptCh <- AcceptedClient{Stream: peer, Close: peer.Close}:
			}
		}
	}()
	return acceptCh, nil
}

// udpPeerStream is a virtual stream representing one UDP peer
type udpPeerStream struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      *net.UDPConn
	peer      *net.UDPAddr
	readCh    chan []byte
	removeFn  func()
	idleTimer *time.Timer
}

// Read returns the next datagram from this peer, or an error after udpIdleTimeout of inactivity
func (u *udpPeerStream) Read(p []byte) (int, error) {
	if !u.idleTimer.Stop() {
		select {
		case <-u.idleTimer.C:
		default:
		}
	}
	u.idleTimer.Reset(udpIdleTimeout)
	select {
	case <-u.ctx.Done():
		return 0, io.EOF
	case packet, ok := <-u.readCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, packet), nil
	case <-u.idleTimer.C:
		return 0, &net.OpError{Op: "read", Net: "udp", Source: u.peer, Err: os.ErrDeadlineExceeded}
	}
}

// Write sends a datagram to the peer via the shared UDP socket
func (u *udpPeerStream) Write(p []byte) (int, error) {
	if u.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return u.conn.WriteToUDP(p, u.peer)
}

// Close cancels this peer stream and removes it from the acceptor
func (u *udpPeerStream) Close() error {
	u.cancel()
	u.removeFn()
	return nil
}

// deliver queues a packet for reading; returns false if the buffer is full or the stream is closed
func (u *udpPeerStream) deliver(packet []byte) bool {
	if u.ctx.Err() != nil {
		return false
	}
	select {
	case u.readCh <- packet:
		return true
	default:
		return false
	}
}
