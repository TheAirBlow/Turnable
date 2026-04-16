package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/sctp"
)

const (
	sctpStreamID            = 0               // SCTP stream ID used by this transport
	sctpMaxReceiveBuffer    = 4 * 1024 * 1024 // Max SCTP receive buffer size
	sctpMaxMessageSize      = 64 * 1024       // Max SCTP message size accepted by the association
	sctpRetransmitTimeoutMs = 2000            // Maximum SCTP retransmit timeout in milliseconds
)

// SCTPHandler provides an SCTP transport layer for reliability
type SCTPHandler struct{}

// ID returns the unique transport ID.
func (D *SCTPHandler) ID() string {
	return "sctp"
}

// WrapClient initializes one outbound SCTP association and stream.
func (D *SCTPHandler) WrapClient(stream io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	assoc, err := sctp.Client(sctp.Config{
		Name:                 "turnable-transport-sctp-client",
		NetConn:              &sctpStreamNetConn{stream: stream},
		MaxReceiveBufferSize: sctpMaxReceiveBuffer,
		MaxMessageSize:       sctpMaxMessageSize,
		RTOMax:               sctpRetransmitTimeoutMs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client sctp association: %w", err)
	}

	sctpStream, err := assoc.OpenStream(sctpStreamID, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		_ = assoc.Close()
		return nil, fmt.Errorf("failed to open sctp stream: %w", err)
	}

	return &managedSCTPConn{base: stream, assoc: assoc, stream: sctpStream}, nil
}

// WrapServer initializes one inbound SCTP association and accepts one stream.
func (D *SCTPHandler) WrapServer(stream io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	assoc, err := sctp.Server(sctp.Config{
		Name:                 "turnable-transport-sctp-server",
		NetConn:              &sctpStreamNetConn{stream: stream},
		MaxReceiveBufferSize: sctpMaxReceiveBuffer,
		MaxMessageSize:       sctpMaxMessageSize,
		RTOMax:               sctpRetransmitTimeoutMs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create server sctp association: %w", err)
	}

	sctpStream, err := assoc.AcceptStream()
	if err != nil {
		_ = assoc.Close()
		return nil, fmt.Errorf("failed to accept sctp stream: %w", err)
	}

	return &managedSCTPConn{base: stream, assoc: assoc, stream: sctpStream}, nil
}

// managedSCTPConn represents a managed SCTP connection
type managedSCTPConn struct {
	base   io.ReadWriteCloser
	assoc  *sctp.Association
	stream *sctp.Stream

	closeMu  sync.Mutex
	isClosed bool
}

// Read forwards payload bytes out of the underlying SCTP stream.
func (c *managedSCTPConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

// Write forwards payload bytes into the underlying SCTP stream.
func (c *managedSCTPConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

// Close shuts down the stream, association, and underlying transport once.
func (c *managedSCTPConn) Close() error {
	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return nil
	}
	c.isClosed = true
	c.closeMu.Unlock()

	return errors.Join(
		func() error {
			if c.stream == nil {
				return nil
			}
			return c.stream.Close()
		}(),
		func() error {
			if c.assoc == nil {
				return nil
			}
			return c.assoc.Close()
		}(),
		func() error {
			if c.base == nil {
				return nil
			}
			return c.base.Close()
		}(),
	)
}

// sctpStreamNetConn represents an SCTP stream network connection
type sctpStreamNetConn struct {
	stream io.ReadWriteCloser
}

// Read forwards reads to the wrapped stream.
func (c *sctpStreamNetConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

// Write forwards writes to the wrapped stream.
func (c *sctpStreamNetConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

// Close closes the wrapped stream.
func (c *sctpStreamNetConn) Close() error {
	return c.stream.Close()
}

// LocalAddr returns the wrapped stream's local address when available.
func (c *sctpStreamNetConn) LocalAddr() net.Addr {
	if conn, ok := c.stream.(net.Conn); ok {
		return conn.LocalAddr()
	}
	return sctpDummyAddr{}
}

// RemoteAddr returns the wrapped stream's remote address when available.
func (c *sctpStreamNetConn) RemoteAddr() net.Addr {
	if conn, ok := c.stream.(net.Conn); ok {
		return conn.RemoteAddr()
	}
	return sctpDummyAddr{}
}

// SetDeadline forwards deadline configuration to the wrapped stream when supported.
func (c *sctpStreamNetConn) SetDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetDeadline(time.Time) error }); ok {
		return conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline forwards read-deadline configuration to the wrapped stream when supported.
func (c *sctpStreamNetConn) SetReadDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline forwards write-deadline configuration to the wrapped stream when supported.
func (c *sctpStreamNetConn) SetWriteDeadline(t time.Time) error {
	if conn, ok := c.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return conn.SetWriteDeadline(t)
	}
	return nil
}

// sctpDummyAddr provides a synthetic address when the wrapped stream is not a net.Conn
type sctpDummyAddr struct{}

// Network returns the synthetic network name used for the SCTP transport.
func (sctpDummyAddr) Network() string { return "sctp-transport" }

// String returns the synthetic address string used for the SCTP transport.
func (sctpDummyAddr) String() string { return "sctp-transport" }
