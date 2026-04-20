package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	kcpWindowSize      = 1024 // KCP send/receive window size
	kcpUpdateMs        = 10   // KCP update interval in milliseconds
	kcpControlUpdateMs = 1    // KCP update interval for control channels
	kcpResend          = 2    // Fast resend after 2 duplicate ACKs
	// kcpDataResend enables fast resend for data channels.  Burst-level peer
	// affinity in the DRR scheduler keeps structural reordering low enough that
	// a threshold of 2 duplicate ACKs rarely triggers spuriously, while
	// recovering from genuine loss in ~1 RTT instead of a full RTO (200 ms+).
	kcpDataResend    = 2
	kcpDisableCC     = 1               // Disable KCP congestion control
	kcpMTU           = 1418            // DTLS MTU excluding the overhead
	kcpReadWriteBuff = 2 * 1024 * 1024 // Read/write buffer size for the session
	kcpConversation  = 1               // Conversation ID for this transport channel
)

// KCPHandler represents a KCP transport handler
type KCPHandler struct{}

// ID returns the unique ID of this handler
func (D *KCPHandler) ID() string {
	return "kcp"
}

// WrapClient wraps a client connection into a reliable stream
func (D *KCPHandler) WrapClient(conn net.Conn) (net.Conn, error) {
	return WrapKCP(conn)
}

// WrapServer wraps a server connection into a reliable stream
func (D *KCPHandler) WrapServer(conn net.Conn) (net.Conn, error) {
	return WrapKCP(conn)
}

// WrapKCP initializes a KCP session over a packet-centric net.Conn
func WrapKCP(conn net.Conn) (net.Conn, error) {
	return wrapKCPWithInterval(conn, kcpUpdateMs, kcpDataResend)
}

// WrapControlKCP initializes a KCP session optimized for control channels that need to drain instantly.
func WrapControlKCP(conn net.Conn) (net.Conn, error) {
	return wrapKCPWithInterval(conn, kcpControlUpdateMs, kcpResend)
}

// wrapKCPWithInterval initializes a KCP session with a given update interval in milliseconds
func wrapKCPWithInterval(conn net.Conn, intervalMs int, resend int) (net.Conn, error) {
	pc := &connPacketConn{Conn: conn}
	session, err := kcp.NewConn3(kcpConversation, pc.LocalAddr(), nil, 0, 0, pc)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kcp session: %w", err)
	}

	session.SetNoDelay(1, intervalMs, resend, kcpDisableCC)
	session.SetWindowSize(kcpWindowSize, kcpWindowSize)
	session.SetACKNoDelay(true)
	session.SetStreamMode(true)
	session.SetWriteDelay(false)
	_ = session.SetReadBuffer(kcpReadWriteBuff)
	_ = session.SetWriteBuffer(kcpReadWriteBuff)
	_ = session.SetMtu(kcpMTU)

	return &managedKCPConn{underlying: conn, packetConn: pc, session: session}, nil
}

// managedKCPConn wraps a KCP session and implements net.Conn
type managedKCPConn struct {
	underlying net.Conn
	packetConn net.PacketConn
	session    *kcp.UDPSession

	closeOnce sync.Once
}

// Read reads from the KCP session
func (c *managedKCPConn) Read(p []byte) (int, error) { return c.session.Read(p) }

// Write writes to the KCP session
func (c *managedKCPConn) Write(p []byte) (int, error) { return c.session.Write(p) }

// Close closes the KCP session and underlying connection
func (c *managedKCPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = errors.Join(
			func() error {
				if c.session == nil {
					return nil
				}
				return c.session.Close()
			}(),
			func() error {
				if c.underlying == nil {
					return nil
				}
				return c.underlying.Close()
			}(),
		)
	})
	return err
}

// LocalAddr returns the local address of the underlying connection
func (c *managedKCPConn) LocalAddr() net.Addr { return c.underlying.LocalAddr() }

// RemoteAddr returns the remote address of the underlying connection
func (c *managedKCPConn) RemoteAddr() net.Addr { return c.underlying.RemoteAddr() }

// SetDeadline sets the read and write deadline on the KCP session
func (c *managedKCPConn) SetDeadline(t time.Time) error { return c.session.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the KCP session
func (c *managedKCPConn) SetReadDeadline(t time.Time) error { return c.session.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the KCP session
func (c *managedKCPConn) SetWriteDeadline(t time.Time) error { return c.session.SetWriteDeadline(t) }

// connPacketConn adapts a packet-centric net.Conn to net.PacketConn
type connPacketConn struct {
	net.Conn
}

// ReadFrom reads a packet and returns the local address as source
func (c *connPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.Conn.LocalAddr(), err
}

// WriteTo writes a packet, ignoring the destination address
func (c *connPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}
