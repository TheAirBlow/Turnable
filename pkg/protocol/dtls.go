package protocol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const (
	dtlsMTU              = 1440            // DTLS record payload limit
	dtlsHandshakeTimeout = 5 * time.Second // DTLS handshake timeout
)

// DTLSHandler represents a DTLS session handler
type DTLSHandler struct {
	running atomic.Bool

	listener net.Listener
	log      *slog.Logger
}

// ID returns the unique ID of this handler
func (D *DTLSHandler) ID() string {
	return "dtls"
}

// Start starts the server listener
func (D *DTLSHandler) Start(listenAddr string) error {
	if !D.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid listen port %q: %w", portStr, err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	if addr.IP == nil {
		return fmt.Errorf("invalid listen IP: %q", host)
	}

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return fmt.Errorf("failed to generate dtls certificate: %w", err)
	}

	listener, err := dtls.ListenWithOptions("udp", addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithMTU(dtlsMTU),
	)
	if err != nil {
		return fmt.Errorf("dtls listen failed: %w", err)
	}

	D.listener = listener

	D.log.Info("dtls listener started", "listen_addr", addr.String())
	success = true
	return nil
}

// Stop stops the server listener
func (D *DTLSHandler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	listener := D.listener
	D.listener = nil

	if listener == nil {
		return nil
	}
	err := listener.Close()
	if err != nil {
		D.log.Warn("dtls listener stop failed", "error", err)
		return err
	}
	D.log.Info("dtls listener stopped")
	return nil
}

// AcceptClients accepts new server clients
func (D *DTLSHandler) AcceptClients(ctx context.Context) (<-chan ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	out := make(chan ServerClient)
	listener := D.listener

	go func() {
		defer close(out)

		if listener == nil {
			return
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					D.log.Warn("dtls accept failed", "error", err)
					continue
				}
			}

			go func(conn net.Conn) {
				if dtlsConn, ok := conn.(*dtls.Conn); ok {
					D.log.Debug("dtls server handshake started", "addr", conn.RemoteAddr())
					if err := dtlsConn.HandshakeContext(ctx); err != nil {
						D.log.Warn("dtls handshake failed", "addr", conn.RemoteAddr(), "error", err)
						_ = conn.Close()
						return
					}
					D.log.Debug("dtls server handshake completed", "addr", conn.RemoteAddr())
				}

				select {
				case out <- ServerClient{Address: conn.RemoteAddr(), Conn: conn}:
				case <-ctx.Done():
					_ = conn.Close()
				}
			}(conn)
		}
	}()

	return out, nil
}

// Connect connects to a remote server directly or via TURN
func (D *DTLSHandler) Connect(ctx context.Context, dest net.Addr, relay TURNInfo, forceTURN bool) (net.Conn, error) {
	if D.log == nil {
		D.log = slog.Default()
	}
	if dest == nil {
		return nil, errors.New("dtls connect requires destination address")
	}

	if forceTURN {
		D.log.Debug("dtls connect using forced turn relay")
		underlay, remoteAddr, err := openTURNUnderlay(relay, dest, "dtls", D.log)
		if err != nil {
			return nil, err
		}
		conn, err := D.connectPacketConn(ctx, underlay, remoteAddr)
		if err != nil {
			_ = underlay.Close()
			return nil, err
		}
		return conn, nil
	}

	underlay, remoteAddr, err := openDirectUnderlay(dest, "dtls", D.log)
	if err != nil {
		return nil, err
	}

	conn, err := D.connectPacketConn(ctx, underlay, remoteAddr)
	if err == nil {
		D.log.Debug("dtls connect established via direct underlay")
		return conn, nil
	}

	_ = underlay.Close()

	if relay.Address == "" {
		return nil, err
	}

	D.log.Info("dtls direct connect failed, falling back to turn", "error", err)
	turnUnderlay, turnRemote, turnErr := openTURNUnderlay(relay, dest, "dtls", D.log)
	if turnErr != nil {
		return nil, errors.Join(err, turnErr)
	}
	conn, connErr := D.connectPacketConn(ctx, turnUnderlay, turnRemote)
	if connErr != nil {
		_ = turnUnderlay.Close()
		return nil, errors.Join(err, connErr)
	}

	D.log.Debug("dtls connect established via turn relay")
	return conn, nil
}

// SetLogger changes the slog logger instance
func (D *DTLSHandler) SetLogger(log *slog.Logger) {
	D.log = log

	if D.log == nil {
		D.log = slog.Default()
	}
}

// connectPacketConn upgrades a packet underlay into an established DTLS session
func (D *DTLSHandler) connectPacketConn(ctx context.Context, underlay net.PacketConn, remoteAddr net.Addr) (net.Conn, error) {
	if underlay == nil {
		return nil, errors.New("dtls connect requires packet underlay")
	}
	if remoteAddr == nil {
		return nil, errors.New("dtls connect requires remote address")
	}

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dtls certificate: %w", err)
	}

	conn, err := dtls.ClientWithOptions(underlay, remoteAddr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMTU(dtlsMTU),
	)

	if err != nil {
		return nil, fmt.Errorf("dtls client init failed: %w", err)
	}

	D.log.Debug("dtls client initialized", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())

	_ = conn.SetDeadline(time.Now().Add(dtlsHandshakeTimeout))

	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls client handshake failed: %w", err)
	}

	_ = conn.SetDeadline(time.Time{})

	D.log.Debug("dtls client handshake completed", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())

	return &dtlsClientConn{
		Conn:     conn,
		underlay: underlay,
	}, nil
}

// dtlsClientConn wraps a DTLS connection and closes the underlay on Close
type dtlsClientConn struct {
	*dtls.Conn
	underlay  net.PacketConn
	closeOnce sync.Once
}

// Close closes both the DTLS connection and the underlay
func (c *dtlsClientConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = errors.Join(c.Conn.Close(), c.underlay.Close())
	})
	return err
}
