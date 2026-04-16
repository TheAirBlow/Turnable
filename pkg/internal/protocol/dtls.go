package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

const relayDTLSMTU = 1200 // DTLS MTU used for every session

// DTLSHandler manages DTLS listener/session lifecycle.
type DTLSHandler struct {
	mu sync.Mutex

	listener net.Listener
	conn     io.ReadWriteCloser
}

// ID returns the unique protocol identifier.
func (D *DTLSHandler) ID() string {
	return "dtls"
}

// Start starts the relay-side DTLS listener.
func (D *DTLSHandler) Start(config config.ServerConfig) error {
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
		dtls.WithMTU(relayDTLSMTU),
	)
	if err != nil {
		return fmt.Errorf("dtls listen failed: %w", err)
	}

	D.mu.Lock()
	defer D.mu.Unlock()

	if D.listener != nil {
		_ = D.listener.Close()
	}
	D.listener = listener
	slog.Info("dtls listener started", "listen_addr", addr.String())
	return nil
}

// Stop stops the relay-side DTLS listener.
func (D *DTLSHandler) Stop() error {
	D.mu.Lock()
	listener := D.listener
	D.listener = nil
	D.mu.Unlock()

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

// Connect establishes a DTLS client session to the provided destination.
func (D *DTLSHandler) Connect(dest net.Addr, relay RelayInfo, forceTURN bool) (io.ReadWriteCloser, error) {
	slog.Info("dtls connect started", "dest", dest, "force_turn", forceTURN)
	conn, err := D.connectClient(context.Background(), dest, relay, forceTURN, nil)
	if err != nil {
		slog.Warn("dtls connect failed", "dest", dest, "force_turn", forceTURN, "error", err)
		return nil, err
	}

	D.mu.Lock()
	if D.conn != nil {
		_ = D.conn.Close()
	}
	D.conn = conn
	D.mu.Unlock()

	slog.Info("dtls connect established", "dest", dest)
	return conn, nil
}

// ConnectRaw establishes a DTLS client session WITHOUT storing it in D.conn.
func (D *DTLSHandler) ConnectRaw(dest net.Addr, relay RelayInfo, forceTURN bool) (io.ReadWriteCloser, error) {
	return D.connectClient(context.Background(), dest, relay, forceTURN, nil)
}

// ConnectRawWithLogger is like ConnectRaw but uses the provided logger for debug output
func (D *DTLSHandler) ConnectRawWithLogger(dest net.Addr, relay RelayInfo, forceTURN bool, log *slog.Logger) (io.ReadWriteCloser, error) {
	return D.connectClient(context.Background(), dest, relay, forceTURN, log)
}

// Disconnect closes the current outbound DTLS session.
func (D *DTLSHandler) Disconnect() error {
	return D.closeConn()
}

// Close forcibly closes the active outbound session.
func (D *DTLSHandler) Close() error {
	return D.closeConn()
}

func (D *DTLSHandler) closeConn() error {
	D.mu.Lock()
	conn := D.conn
	D.conn = nil
	D.mu.Unlock()

	if conn == nil {
		return nil
	}
	if err := conn.Close(); err != nil {
		return err
	}
	return nil
}

// AcceptNewClients emits accepted relay-side DTLS clients.
func (D *DTLSHandler) AcceptNewClients(ctx context.Context) <-chan ServerClient {
	out := make(chan ServerClient)

	D.mu.Lock()
	listener := D.listener
	D.mu.Unlock()

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
				case out <- ServerClient{Address: conn.RemoteAddr(), IO: conn}:
				case <-ctx.Done():
					_ = conn.Close()
				}
			}(conn)
		}
	}()

	return out
}

// connectClient dials the destination directly and falls back to TURN when needed.
func (D *DTLSHandler) connectClient(ctx context.Context, dest net.Addr, relay RelayInfo, forceTURN bool, log *slog.Logger) (io.ReadWriteCloser, error) {
	if log == nil {
		log = slog.Default()
	}
	if dest == nil {
		return nil, errors.New("dtls connect requires destination address")
	}

	if forceTURN {
		log.Debug("dtls connect using forced turn relay")
		return D.connectViaTURN(ctx, relay, dest, log)
	}

	underlay, remoteAddr, err := D.openDirectUnderlay(dest)
	if err != nil {
		return nil, err
	}

	conn, err := D.connectPacketConn(ctx, underlay, remoteAddr, log)
	if err == nil {
		log.Debug("dtls connect established via direct underlay")
		return conn, nil
	}

	_ = underlay.Close()

	if relay.Address == "" {
		return nil, err
	}

	log.Info("dtls direct connect failed, falling back to turn", "error", err)
	conn, turnErr := D.connectViaTURN(ctx, relay, dest, log)
	if turnErr != nil {
		return nil, errors.Join(err, turnErr)
	}

	log.Debug("dtls connect established via turn relay")
	return conn, nil
}

// connectViaTURN iterates TURN servers until one can establish a DTLS session.
func (D *DTLSHandler) connectViaTURN(ctx context.Context, relay RelayInfo, dest net.Addr, log *slog.Logger) (io.ReadWriteCloser, error) {
	servers := relay.Addresses

	if len(servers) == 0 {
		return nil, errors.New("dtls turn fallback requires turn address")
	}
	log.Debug("dtls trying turn servers", "count", len(servers), "servers", strings.Join(servers, ","))

	var lastErr error
	for i, address := range servers {
		candidate := relay
		candidate.Address = address
		log.Debug("dtls trying turn candidate", "index", i+1, "count", len(servers), "server", address, "dest", dest.String())

		underlay, remoteAddr, err := D.openTURNUnderlay(candidate, dest, log)
		if err != nil {
			lastErr = err
			log.Warn("dtls turn candidate failed", "index", i+1, "count", len(servers), "server", address, "error", err)
			continue
		}

		conn, err := D.connectPacketConn(ctx, underlay, remoteAddr, log)
		if err != nil {
			_ = underlay.Close()
			lastErr = err
			log.Warn("dtls turn candidate handshake failed", "index", i+1, "count", len(servers), "server", address, "error", err)
			continue
		}

		log.Debug("dtls turn candidate selected", "index", i+1, "count", len(servers), "server", address)
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

// openDirectUnderlay opens an unconnected UDP socket for use with the DTLS client.
// The returned conn is wrapped to fall back to Write() if the OS pre-connects the socket
// after the first send (which would otherwise make pion's internal WriteTo calls fail).
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

	return &adaptiveUDPConn{UDPConn: underlay}, udpAddr, nil
}

// adaptiveUDPConn wraps *net.UDPConn so that WriteTo falls back to Write when
// the socket has been implicitly connected by the OS (which rejects WriteTo).
type adaptiveUDPConn struct {
	*net.UDPConn
}

func (c *adaptiveUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	if err != nil && strings.Contains(err.Error(), "use of WriteTo with pre-connected connection") {
		return c.UDPConn.Write(b)
	}
	return n, err
}

// openTURNUnderlay allocates a TURN relay socket and permission for the peer.
func (D *DTLSHandler) openTURNUnderlay(relay RelayInfo, dest net.Addr, log *slog.Logger) (net.PacketConn, net.Addr, error) {
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

	baseConn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open local udp socket for turn: %w", err)
	}
	log.Debug("dtls turn base socket opened", "network", network, "local", baseConn.LocalAddr().String(), "turn_server", relay.Address)

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: relay.Address,
		TURNServerAddr: relay.Address,
		Username:       relay.Username,
		Password:       relay.Password,
		Conn:           baseConn,
		LoggerFactory:  &common.SlogLoggerFactory{Log: log},
	})
	if err != nil {
		_ = baseConn.Close()
		return nil, nil, fmt.Errorf("failed to create turn client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		_ = baseConn.Close()
		return nil, nil, fmt.Errorf("failed to start turn client listener: %w", err)
	}

	log.Debug("dtls turn client listener started", "turn_server", relay.Address)
	allocation, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = baseConn.Close()
		return nil, nil, fmt.Errorf("failed to allocate turn relay: %w", err)
	}

	log.Debug("dtls turn allocation created", "turn_server", relay.Address)
	if err := client.CreatePermission(dest); err != nil {
		_ = allocation.Close()
		client.Close()
		_ = baseConn.Close()
		return nil, nil, fmt.Errorf("failed to create turn permission for %s: %w", dest.String(), err)
	}

	log.Debug("dtls turn permission created", "peer", dest.String(), "turn_server", relay.Address)
	return &turnPacketConn{
		PacketConn: allocation,
		baseConn:   baseConn,
		client:     client,
	}, dest, nil
}

// connectPacketConn upgrades a packet underlay into an established DTLS session.
func (D *DTLSHandler) connectPacketConn(ctx context.Context, underlay net.PacketConn, remoteAddr net.Addr, log *slog.Logger) (io.ReadWriteCloser, error) {
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
		dtls.WithMTU(relayDTLSMTU),
	)

	if err != nil {
		return nil, fmt.Errorf("dtls client init failed: %w", err)
	}

	log.Debug("dtls client initialized", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls client handshake failed: %w", err)
	}

	log.Debug("dtls client handshake completed", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())
	return &dtlsClientConn{
		Conn: conn,
	}, nil
}

// dtlsClientConn wraps a DTLS client connection together with its packet underlay.
type dtlsClientConn struct {
	*dtls.Conn
	closeOnce sync.Once
	closeErr  error
}

// Close tears down both the DTLS session and the underlying packet transport.
func (c *dtlsClientConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// turnPacketConn wraps a TURN allocation together with the client and base socket.
type turnPacketConn struct {
	net.PacketConn
	baseConn  net.PacketConn
	client    *turn.Client
	closeOnce sync.Once
	closeErr  error
}

// Close releases the TURN allocation, client, and base socket.
func (c *turnPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.client != nil {
			c.client.Close()
		}
		if c.baseConn != nil {
			c.closeErr = errors.Join(c.closeErr, c.baseConn.Close())
		}
	})
	return c.closeErr
}
