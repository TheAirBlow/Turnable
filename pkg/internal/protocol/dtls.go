package protocol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

const (
	// dtlsMTU is the DTLS record payload limit; with 20 bytes encryption overhead,
	// upper layers have ~1420 bytes of usable plaintext per datagram
	dtlsMTU = 1440
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
func (D *DTLSHandler) Start(config config.ServerConfig) error {
	if !D.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	if !config.Relay.Enabled {
		return errors.New("dtls relay start requires relay mode to be enabled")
	}
	if config.Relay.Port == nil {
		return errors.New("dtls relay start requires server port")
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(config.Relay.PublicIP),
		Port: *config.Relay.Port,
	}
	if addr.IP == nil {
		return fmt.Errorf("invalid relay listen ip %q", config.Relay.PublicIP)
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

	slog.Info("dtls listener started", "listen_addr", addr.String())
	success = true
	return nil
}

// Stop stops the server listener
func (D *DTLSHandler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	listener := D.listener
	D.listener = nil

	if listener == nil {
		return nil
	}
	err := listener.Close()
	if err != nil {
		slog.Warn("dtls listener stop failed", "error", err)
		return err
	}
	slog.Info("dtls listener stopped")
	return nil
}

// AcceptClients accepts new server clients
func (D *DTLSHandler) AcceptClients(ctx context.Context) (<-chan ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
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
					slog.Warn("dtls accept failed", "error", err)
					continue
				}
			}

			go func(conn net.Conn) {
				if dtlsConn, ok := conn.(*dtls.Conn); ok {
					slog.Debug("dtls server handshake started", "addr", conn.RemoteAddr())
					if err := dtlsConn.HandshakeContext(ctx); err != nil {
						slog.Warn("dtls handshake failed", "addr", conn.RemoteAddr(), "error", err)
						_ = conn.Close()
						return
					}
					slog.Debug("dtls server handshake completed", "addr", conn.RemoteAddr())
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
func (D *DTLSHandler) Connect(ctx context.Context, dest net.Addr, relay RelayInfo, forceTURN bool) (net.Conn, error) {
	if D.log == nil {
		D.log = slog.Default()
	}

	if dest == nil {
		return nil, errors.New("dtls connect requires destination address")
	}

	if forceTURN {
		D.log.Debug("dtls connect using forced turn relay")
		return D.connectViaTURN(ctx, relay, dest)
	}

	underlay, remoteAddr, err := D.openDirectUnderlay(dest)
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
	conn, turnErr := D.connectViaTURN(ctx, relay, dest)
	if turnErr != nil {
		return nil, errors.Join(err, turnErr)
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

// connectViaTURN attempts to connect to the remote server via one of the provided TURN servers
func (D *DTLSHandler) connectViaTURN(ctx context.Context, relay RelayInfo, dest net.Addr) (net.Conn, error) {
	servers := relay.Addresses

	if len(servers) == 0 {
		return nil, errors.New("dtls turn fallback requires turn address")
	}
	D.log.Debug("dtls trying turn servers", "count", len(servers), "servers", strings.Join(servers, ","))

	var lastErr error
	for i, address := range servers {
		candidate := relay
		candidate.Address = address
		D.log.Debug("dtls trying turn candidate", "index", i+1, "count", len(servers), "server", address, "dest", dest.String())

		underlay, remoteAddr, err := D.openTURNUnderlay(candidate, dest)
		if err != nil {
			lastErr = err
			D.log.Warn("dtls turn candidate failed", "index", i+1, "count", len(servers), "server", address, "error", err)
			continue
		}

		conn, err := D.connectPacketConn(ctx, underlay, remoteAddr)
		if err != nil {
			_ = underlay.Close()
			lastErr = err
			D.log.Warn("dtls turn candidate handshake failed", "index", i+1, "count", len(servers), "server", address, "error", err)
			continue
		}

		D.log.Debug("dtls turn candidate selected", "index", i+1, "count", len(servers), "server", address)
		return conn, nil
	}

	if lastErr == nil {
		lastErr = errors.New("failed to establish dtls over turn")
	}
	if strings.Contains(lastErr.Error(), "Allocation Quota Reached") {
		return nil, fmt.Errorf("%w: %w", ErrQuotaReached, lastErr)
	}
	return nil, lastErr
}

// openDirectUnderlay opens an unconnected UDP socket for use with the DTLS client
func (D *DTLSHandler) openDirectUnderlay(dest net.Addr) (net.PacketConn, net.Addr, error) {
	udpAddr, ok := dest.(*net.UDPAddr)
	if !ok {
		resolved, err := net.ResolveUDPAddr("udp", dest.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve udp destination: %w", err)
		}
		udpAddr = resolved
	}

	network := "udp4"
	if udpAddr.IP != nil && udpAddr.IP.To4() == nil {
		network = "udp6"
	}

	underlay, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open direct udp underlay: %w", err)
	}
	slog.Debug("dtls direct underlay opened", "local", underlay.LocalAddr().String(), "remote", udpAddr.String())

	return underlay, udpAddr, nil
}

// openTURNUnderlay allocates a TURN relay socket for use with the DTLS client
func (D *DTLSHandler) openTURNUnderlay(relay RelayInfo, dest net.Addr) (net.PacketConn, net.Addr, error) {
	if relay.Address == "" {
		return nil, nil, errors.New("dtls turn fallback requires turn address")
	}
	if relay.Username == "" {
		return nil, nil, errors.New("dtls turn fallback requires turn username")
	}
	if relay.Password == "" {
		return nil, nil, errors.New("dtls turn fallback requires turn password")
	}

	network := "udp4"
	if udpAddr, ok := dest.(*net.UDPAddr); ok && udpAddr.IP != nil && udpAddr.IP.To4() == nil {
		network = "udp6"
	}

	underlay, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open local udp socket for turn: %w", err)
	}
	D.log.Debug("dtls turn base socket opened", "network", network, "local", underlay.LocalAddr().String(), "turn_server", relay.Address)

	infoLevel := slog.LevelInfo
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: relay.Address,
		TURNServerAddr: relay.Address,
		Username:       relay.Username,
		Password:       relay.Password,
		Conn:           underlay,
		LoggerFactory:  &common.SlogLoggerFactory{Log: D.log, Level: &infoLevel},
	})
	if err != nil {
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to create turn client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to start turn client listener: %w", err)
	}

	D.log.Debug("dtls turn client listener started", "turn_server", relay.Address)
	allocation, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to allocate turn relay: %w", err)
	}

	D.log.Debug("dtls turn allocation created", "turn_server", relay.Address)
	if err := client.CreatePermission(dest); err != nil {
		_ = allocation.Close()
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to create turn permission for %s: %w", dest.String(), err)
	}

	D.log.Debug("dtls turn permission created", "peer", dest.String(), "turn_server", relay.Address)
	return &turnPacketConn{
		PacketConn: allocation,
		underlay:   underlay,
		client:     client,
	}, dest, nil
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
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls client handshake failed: %w", err)
	}

	D.log.Debug("dtls client handshake completed", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())
	return &dtlsClientConn{
		Conn:     conn,
		underlay: underlay,
	}, nil
}

// dtlsClientConn represents a DTLS connection that automatically closes the underlay
type dtlsClientConn struct {
	*dtls.Conn
	underlay  net.PacketConn
	closeOnce sync.Once
}

// Close closes both the DTLS connection and the underlay
func (c *dtlsClientConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		dtlsErr := c.Conn.Close()
		underlayErr := c.underlay.Close()
		if dtlsErr != nil {
			err = dtlsErr
			return
		}
		err = underlayErr
	})
	return err
}

// turnPacketConn represents a TURN packet connection that automatically closes the client and the underlay
type turnPacketConn struct {
	net.PacketConn
	underlay  net.PacketConn
	client    *turn.Client
	closeOnce sync.Once
}

// Close closes the TURN packet connection, the client and the underlay
func (c *turnPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.PacketConn.Close()
		if c.client != nil {
			c.client.Close()
		}
		if c.underlay != nil {
			err = errors.Join(err, c.underlay.Close())
		}
	})
	return err
}
