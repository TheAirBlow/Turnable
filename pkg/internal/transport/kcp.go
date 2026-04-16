package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	kcpMaxFrameSize  = 0xFFFF          // Maximum framed packet size accepted by the stream adapter
	kcpWindowSize    = 512             // KCP send/receive window size
	kcpUpdateMs      = 40              // KCP update interval in milliseconds
	kcpResend        = 2               // Fast resend after 2 duplicate ACKs
	kcpDisableCC     = 1               // Disable KCP congestion control
	kcpMTU           = 1200            // Maximum KCP MTU used for this transport
	kcpReadWriteBuff = 2 * 1024 * 1024 // Read/write buffer size for the session
	kcpConversation  = 1               // Conversation ID for this transport channel
)

// KCPHandler provides a KCP transport layer for reliability
type KCPHandler struct{}

// ID returns the unique transport ID.
func (D *KCPHandler) ID() string {
	return "kcp"
}

// WrapPacketConn initializes one KCP session directly over a net.PacketConn (e.g. MultiPeerConn).
func (D *KCPHandler) WrapPacketConn(pc net.PacketConn) (io.ReadWriteCloser, error) {
	session, err := kcp.NewConn3(kcpConversation, kcpDummyAddr{}, nil, 0, 0, pc)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kcp session over packetconn: %w", err)
	}
	configureKCP(session)
	return &managedKCPConn{packetConn: pc, session: session}, nil
}

// WrapClient initializes one client-side KCP session over a framed packet adapter.
func (D *KCPHandler) WrapClient(stream io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	packetConn := &kcpStreamPacketConn{
		stream: common.WrapBufferedReadStream(stream, 64*1024),
	}
	session, err := kcp.NewConn3(kcpConversation, kcpDummyAddr{}, nil, 0, 0, packetConn)
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("failed to initialize kcp client session: %w", err)
	}
	configureKCP(session)
	return &managedKCPConn{base: stream, packetConn: packetConn, session: session}, nil
}

// WrapServer initializes one server-side KCP session over a framed packet adapter.
func (D *KCPHandler) WrapServer(stream io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	packetConn := &kcpStreamPacketConn{
		stream: common.WrapBufferedReadStream(stream, 64*1024),
	}
	session, err := kcp.NewConn3(kcpConversation, kcpDummyAddr{}, nil, 0, 0, packetConn)
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("failed to initialize kcp server session: %w", err)
	}
	configureKCP(session)
	return &managedKCPConn{base: stream, packetConn: packetConn, session: session}, nil
}

// configureKCP applies the transport-specific KCP tuning used by this project.
func configureKCP(session *kcp.UDPSession) {
	session.SetNoDelay(1, kcpUpdateMs, kcpResend, kcpDisableCC)
	session.SetWindowSize(kcpWindowSize, kcpWindowSize)
	session.SetACKNoDelay(true)
	session.SetStreamMode(true)
	session.SetWriteDelay(false)
	_ = session.SetReadBuffer(kcpReadWriteBuff)
	_ = session.SetWriteBuffer(kcpReadWriteBuff)
	if !session.SetMtu(kcpMTU) {
		_ = session.SetMtu(1200)
	}
}

// managedKCPConn represents a managed KCP connection
type managedKCPConn struct {
	base       io.ReadWriteCloser
	packetConn net.PacketConn
	session    *kcp.UDPSession

	closeMu  sync.Mutex
	isClosed bool
}

// Read forwards payload bytes out of the underlying KCP session.
func (c *managedKCPConn) Read(p []byte) (int, error) {
	return c.session.Read(p)
}

// Write forwards payload bytes into the underlying KCP session.
func (c *managedKCPConn) Write(p []byte) (int, error) {
	return c.session.Write(p)
}

// Close shuts down the session, packet adapter, and underlying stream once.
func (c *managedKCPConn) Close() error {
	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return nil
	}
	c.isClosed = true
	c.closeMu.Unlock()

	return errors.Join(
		func() error {
			if c.session == nil {
				return nil
			}
			return c.session.Close()
		}(),
		func() error {
			if c.packetConn == nil {
				return nil
			}
			return c.packetConn.Close()
		}(),
		func() error {
			if c.base == nil {
				return nil
			}
			return c.base.Close()
		}(),
	)
}

// kcpStreamPacketConn represents a KCP stream network connection
type kcpStreamPacketConn struct {
	stream io.ReadWriteCloser
	write  sync.Mutex
}

// ReadFrom decodes a length-prefixed frame from the backing stream.
func (c *kcpStreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	header := make([]byte, 2)
	if _, err := common.ReadFullRetry(c.stream, header); err != nil {
		return 0, nil, err
	}

	size := int(binary.BigEndian.Uint16(header))
	if size > kcpMaxFrameSize {
		return 0, nil, fmt.Errorf("kcp packet too large: %d", size)
	}

	frame := make([]byte, size)
	if size > 0 {
		if _, err := common.ReadFullRetry(c.stream, frame); err != nil {
			return 0, nil, err
		}
	}

	n = copy(p, frame)
	return n, kcpDummyAddr{}, nil
}

// WriteTo encodes one KCP packet as a length-prefixed frame on the backing stream.
func (c *kcpStreamPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if len(p) > kcpMaxFrameSize {
		return 0, fmt.Errorf("kcp packet too large: %d", len(p))
	}

	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)

	c.write.Lock()
	defer c.write.Unlock()

	if err := common.WriteFullRetry(c.stream, frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying byte stream.
func (c *kcpStreamPacketConn) Close() error {
	return c.stream.Close()
}

// LocalAddr returns the wrapped stream's local address when available.
func (c *kcpStreamPacketConn) LocalAddr() net.Addr {
	if conn, ok := c.stream.(net.Conn); ok {
		return conn.LocalAddr()
	}
	return kcpDummyAddr{}
}

// SetDeadline forwards deadline configuration to the wrapped stream when supported.
func (c *kcpStreamPacketConn) SetDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetDeadline(time.Time) error }); ok {
		return conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline forwards read-deadline configuration to the wrapped stream when supported.
func (c *kcpStreamPacketConn) SetReadDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline forwards write-deadline configuration to the wrapped stream when supported.
func (c *kcpStreamPacketConn) SetWriteDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return conn.SetWriteDeadline(t)
	}
	return nil
}

// kcpDummyAddr provides a synthetic address when the wrapped stream is not a net.Conn
type kcpDummyAddr struct{}

// Network returns the synthetic network name used for the KCP transport.
func (kcpDummyAddr) Network() string { return "kcp-transport" }

// String returns the synthetic address string used for the KCP transport.
func (kcpDummyAddr) String() string { return "kcp-transport" }
