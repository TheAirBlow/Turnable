package protocol

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/config"
)

// NoneHandler passes traffic as raw UDP without any encryption or framing
type NoneHandler struct {
	log *slog.Logger
}

// ID returns the unique ID of this handler
func (N *NoneHandler) ID() string { return "none" }

// SetLogger changes the slog logger instance
func (N *NoneHandler) SetLogger(log *slog.Logger) {
	N.log = log
	if N.log == nil {
		N.log = slog.Default()
	}
}

// Start starts the server listener
func (N *NoneHandler) Start(_ config.ServerConfig) error {
	return errors.New("none handler does not support server mode")
}

// Stop stops the server listener
func (N *NoneHandler) Stop() error {
	return errors.New("none handler does not support server mode")
}

// AcceptClients accepts new server clients
func (N *NoneHandler) AcceptClients(_ context.Context) (<-chan ServerClient, error) {
	return nil, errors.New("none handler does not support server mode")
}

// Connect connects to a remote server directly or via TURN
func (N *NoneHandler) Connect(ctx context.Context, dest net.Addr, relay RelayInfo, forceTURN bool) (net.Conn, error) {
	if N.log == nil {
		N.log = slog.Default()
	}
	if dest == nil {
		return nil, errors.New("none connect requires destination address")
	}

	if forceTURN {
		N.log.Debug("none connect using forced turn relay")
		underlay, remoteAddr, err := connectViaTURN(relay, dest, "none", N.log)
		if err != nil {
			return nil, err
		}
		N.log.Debug("none connect established via turn relay")
		return newNoneClientConn(underlay, remoteAddr), nil
	}

	underlay, remoteAddr, err := openDirectUnderlay(dest, "none", N.log)
	if err != nil {
		return nil, err
	}

	N.log.Debug("none connect established via direct underlay")
	return newNoneClientConn(underlay, remoteAddr), nil
}

// newNoneClientConn wraps a PacketConn as a net.Conn targeting remote
func newNoneClientConn(underlay net.PacketConn, remote net.Addr) *noneConn {
	return &noneConn{raw: underlay, remote: remote}
}

// noneConn is a net.Conn backed by a raw UDP PacketConn with no encryption
type noneConn struct {
	raw       net.PacketConn
	remote    net.Addr
	closeOnce sync.Once
}

// Read reads the next packet from the underlying PacketConn
func (c *noneConn) Read(b []byte) (int, error) {
	n, _, err := c.raw.ReadFrom(b)
	return n, err
}

// Write sends b to the remote peer
func (c *noneConn) Write(b []byte) (int, error) {
	return c.raw.WriteTo(b, c.remote)
}

// Close closes the underlying PacketConn
func (c *noneConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.raw.Close() })
	return err
}

// LocalAddr returns the local address of the underlying PacketConn
func (c *noneConn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr returns the remote peer address
func (c *noneConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets both read and write deadlines
func (c *noneConn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// SetReadDeadline sets a deadline for future Read calls
func (c *noneConn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline is a no-op since UDP writes are non-blocking
func (c *noneConn) SetWriteDeadline(_ time.Time) error { return nil }
