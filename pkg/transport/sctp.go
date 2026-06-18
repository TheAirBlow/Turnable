package transport

import (
	"errors"
	"fmt"
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
	sctpMTU                 = 1418            // DTLS(1440) - encryption overhead(20) - mux header(2)
)

// SCTPHandler represents an SCTP transport handler
type SCTPHandler struct{}

// ID returns the unique ID of this handler
func (D *SCTPHandler) ID() string {
	return "sctp"
}

// WrapClient wraps a client connection into a reliable stream
func (D *SCTPHandler) WrapClient(conn net.Conn) (net.Conn, error) {
	assoc, err := sctp.Client(sctp.Config{
		Name:                 "turnable-transport-sctp-client",
		NetConn:              conn,
		MaxReceiveBufferSize: sctpMaxReceiveBuffer,
		MaxMessageSize:       sctpMaxMessageSize,
		RTOMax:               sctpRetransmitTimeoutMs,
		MTU:                  sctpMTU,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client sctp association: %w", err)
	}

	stream, err := assoc.OpenStream(sctpStreamID, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		_ = assoc.Close()
		return nil, fmt.Errorf("failed to open sctp stream: %w", err)
	}

	return &managedSCTPConn{underlying: conn, assoc: assoc, stream: stream}, nil
}

// WrapServer wraps a server connection into a reliable stream
func (D *SCTPHandler) WrapServer(conn net.Conn) (net.Conn, error) {
	assoc, err := sctp.Server(sctp.Config{
		Name:                 "turnable-transport-sctp-server",
		NetConn:              conn,
		MaxReceiveBufferSize: sctpMaxReceiveBuffer,
		MaxMessageSize:       sctpMaxMessageSize,
		RTOMax:               sctpRetransmitTimeoutMs,
		MTU:                  sctpMTU,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create server sctp association: %w", err)
	}

	stream, err := assoc.AcceptStream()
	if err != nil {
		_ = assoc.Close()
		return nil, fmt.Errorf("failed to accept sctp stream: %w", err)
	}

	return &managedSCTPConn{underlying: conn, assoc: assoc, stream: stream}, nil
}

// managedSCTPConn wraps an SCTP stream and implements net.Conn
type managedSCTPConn struct {
	underlying net.Conn
	assoc      *sctp.Association
	stream     *sctp.Stream

	closeOnce sync.Once
}

// Read reads from the SCTP stream
func (c *managedSCTPConn) Read(p []byte) (int, error) { return c.stream.Read(p) }

// Write writes to the SCTP stream
func (c *managedSCTPConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

// Close closes the SCTP stream, association, and underlying connection
func (c *managedSCTPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = errors.Join(
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
func (c *managedSCTPConn) LocalAddr() net.Addr { return c.underlying.LocalAddr() }

// RemoteAddr returns the remote address of the underlying connection
func (c *managedSCTPConn) RemoteAddr() net.Addr { return c.underlying.RemoteAddr() }

// SetDeadline sets the read and write deadline on the underlying connection
func (c *managedSCTPConn) SetDeadline(t time.Time) error { return c.underlying.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying connection
func (c *managedSCTPConn) SetReadDeadline(t time.Time) error { return c.underlying.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying connection
func (c *managedSCTPConn) SetWriteDeadline(t time.Time) error {
	return c.underlying.SetWriteDeadline(t)
}
