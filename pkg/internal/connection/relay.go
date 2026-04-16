package connection

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	platformpkg "github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
	transportpkg "github.com/theairblow/turnable/pkg/internal/transport"
)

const (
	relayHandshakeTimeout = 10 * time.Second

	// Hello type bytes sent inside EncryptedTunnel before the hello payload.
	relayHelloTypePrimary   byte = 1
	relayHelloTypeSecondary byte = 2

	// Wire protocol version byte.
	relayHandshakeVersion byte = 1

	// Ack status bytes.
	relayAckOK  byte = 0
	relayAckErr byte = 1

	// Full reconnect backoff parameters.
	fullReconnectInit = 5 * time.Second
	fullReconnectMax  = 30 * time.Second
)

// ErrReconnecting is returned when a full reconnect is in progress.
var ErrReconnecting = errors.New("relay: reconnecting")

// RelayHandler establishes relay-mode authenticated connections on top of a protocol handler.
type RelayHandler struct {
	mu sync.Mutex

	// server-side
	serverConfig *config.ServerConfig
	proto        protocol.Handler
	sessions     sync.Map // sessionUUID string → *relayServerSession

	// client-side
	platform  platformpkg.Handler
	muxClient *VPNMuxClient
	peerConn  *PeerConn
	cancel    context.CancelFunc

	clientConfig    *config.ClientConfig
	sessionUUID     string
	reconnecting    atomic.Bool
	reconnectMu     sync.Mutex
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc
}

// relayServerSession tracks a multi-peer server-side session.
type relayServerSession struct {
	peerConn *PeerConn
	userUUID string
	routeID  string
	fullEnc  bool
}

// relayHandshakeResult holds the authenticated metadata returned after a relay handshake.
type relayHandshakeResult struct {
	Config      *config.ClientConfig
	User        *config.User
	Route       *config.Route
	SessionUUID string
}

// ID returns the unique ID of this handler.
func (D *RelayHandler) ID() string {
	return "relay"
}

// Start starts the relay-side protocol listener.
func (D *RelayHandler) Start(cfg config.ServerConfig) error {
	if !cfg.Relay.Enabled {
		return errors.New("relay mode is not enabled on the server")
	}
	if common.IsNullOrWhiteSpace(cfg.Relay.PublicIP) {
		return errors.New("relay mode requires public_ip")
	}
	if cfg.Relay.Port == nil {
		return errors.New("relay mode requires port")
	}
	if !protocol.HandlerExists(cfg.Relay.Proto) {
		return fmt.Errorf("invalid relay protocol: %s", cfg.Relay.Proto)
	}

	handler, err := protocol.GetHandler(cfg.Relay.Proto)
	if err != nil {
		return err
	}
	if err := handler.Start(cfg); err != nil {
		return err
	}

	D.mu.Lock()
	D.serverConfig = &cfg
	D.proto = handler
	D.mu.Unlock()
	return nil
}

// Stop stops the relay-side protocol listener.
func (D *RelayHandler) Stop() error {
	D.mu.Lock()
	protoHandler := D.proto
	D.serverConfig = nil
	D.proto = nil
	D.mu.Unlock()

	if protoHandler == nil {
		return nil
	}
	return protoHandler.Stop()
}

// Connect establishes a relay client connection and performs the connection-layer handshake.
// The sessionUUID parameter is accepted for API compatibility but the server assigns the UUID.
func (D *RelayHandler) Connect(cfg config.ClientConfig, _ string) error {
	if cfg.Type != D.ID() {
		return fmt.Errorf("invalid connection type %q, expected %q", cfg.Type, D.ID())
	}
	if common.IsNullOrWhiteSpace(cfg.Gateway) {
		return errors.New("no gateway address was provided")
	}

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())

	D.mu.Lock()
	D.clientConfig = &cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel
	D.mu.Unlock()

	if err := D.connectClientSession(); err != nil {
		reconnectCancel()
		return err
	}
	return nil
}

// OpenChannel opens a new vpnmux data channel for the given socket type ("tcp" or "udp").
func (D *RelayHandler) OpenChannel(socketType string) (io.ReadWriteCloser, error) {
	stream, err := D.openChannel()
	if err != nil {
		return nil, err
	}
	if strings.ToLower(socketType) == "udp" {
		return newFramedUDPStream(stream), nil
	}
	return stream, nil
}

// Disconnect gracefully disconnects the current client-side relay session.
func (D *RelayHandler) Disconnect() error {
	D.mu.Lock()
	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""
	D.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if reconnectCancel != nil {
		reconnectCancel()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Disconnect()
		}(),
	)
}

// Close forcibly closes the active client session.
func (D *RelayHandler) Close() error {
	D.mu.Lock()
	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""
	D.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if reconnectCancel != nil {
		reconnectCancel()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Close()
		}(),
	)
}

func (D *RelayHandler) openChannel() (io.ReadWriteCloser, error) {
	if D.reconnecting.Load() {
		return nil, ErrReconnecting
	}

	D.mu.Lock()
	muxClient := D.muxClient
	D.mu.Unlock()

	if muxClient == nil {
		return nil, errors.New("relay: no active mux connection")
	}

	stream, err := muxClient.OpenChannel()
	if err != nil {
		D.mu.Lock()
		if D.muxClient == muxClient {
			D.muxClient = nil
		}
		D.mu.Unlock()
		_ = muxClient.Close()
		return nil, fmt.Errorf("relay: mux channel open failed: %w", err)
	}
	return stream, nil
}

// connectClientSession establishes the platform, underlay, and vpnmux session for the client.
func (D *RelayHandler) connectClientSession() error {
	D.reconnectMu.Lock()
	defer D.reconnectMu.Unlock()

	D.mu.Lock()
	cfg := D.clientConfig
	reconnectCtx := D.reconnectCtx
	oldCancel := D.cancel
	oldPeerConn := D.peerConn
	oldPlatform := D.platform
	oldMux := D.muxClient
	D.mu.Unlock()

	if cfg == nil {
		return errors.New("relay reconnect requires client config")
	}
	if reconnectCtx == nil {
		return errors.New("relay reconnect context is not initialized")
	}

	platformHandler, err := platformpkg.GetHandler(cfg.PlatformID)
	if err != nil {
		return err
	}
	if err := platformHandler.Authorize(cfg.CallID, cfg.Username); err != nil {
		return err
	}

	if os.Getenv("QUIT_AFTER_AUTH") == "1" {
		slog.Info("QUIT_AFTER_AUTH set, quitting...")
		os.Exit(0)
	}

	watchCtx, cancel := context.WithCancel(reconnectCtx)
	events := platformHandler.WatchEvents(watchCtx)

	if err := platformHandler.Connect(); err != nil {
		cancel()
		_ = platformHandler.Close()
		return err
	}

	protoHandler, err := protocol.GetHandler(cfg.Proto)
	if err != nil {
		cancel()
		_ = platformHandler.Disconnect()
		return err
	}

	turnInfo := platformHandler.GetTURNInfo()
	dest, err := net.ResolveUDPAddr("udp", cfg.Gateway)
	if err != nil {
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("invalid relay gateway %q: %w", cfg.Gateway, err)
	}

	relayInfo := protocol.RelayInfo{
		Address:   turnInfo.Address,
		Addresses: append([]string(nil), turnInfo.Addresses...),
		Username:  turnInfo.Username,
		Password:  turnInfo.Password,
	}

	go monitorRelayPlatform(watchCtx, events)

	// Connect peer 0 via raw DTLS.
	peer0Log := slog.With("peer_idx", 0)
	rawConn0, err := protocol.ConnectRawLog(protoHandler, dest, relayInfo, true, peer0Log)
	if err != nil {
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 connect: %w", err)
	}

	// Per-peer EncryptedTunnel - always used regardless of cfg.Encryption.
	// In "handshake" mode it is discarded after the handshake; in "full" mode it stays in PeerConn.
	encTunnel0, err := wrapClientEncryptedStream(rawConn0, cfg.PubKey)
	if err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 encryption init: %w", err)
	}

	// Primary handshake - server assigns session UUID.
	if dc, ok := rawConn0.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Now().Add(relayHandshakeTimeout))
	}
	assignedUUID, err := doClientPrimaryHandshake(encTunnel0, cfg.ToURL(true))
	if dc, ok := rawConn0.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 handshake: %w", err)
	}

	sessionUUIDStr := uuid.UUID(assignedUUID).String()

	// In "full" mode keep the EncryptedTunnel; in "handshake" mode use the raw connection.
	var conn0 io.ReadWriteCloser
	if cfg.Encryption == "full" {
		conn0 = encTunnel0
	} else {
		conn0 = encTunnel0.Underlying()
	}

	// Reconnect factory - all peers (including peer 0) reconnect as secondary peers,
	// since the primary session (KCP/VPNMux) stays alive as long as ≥1 peer is connected.
	makePeerReconnectFn := func(peerIdx int) func(context.Context) (io.ReadWriteCloser, error) {
		peerLog := slog.With("peer_idx", peerIdx)
		return func(ctx context.Context) (io.ReadWriteCloser, error) {
			rawConn, err := protocol.ConnectRawLog(protoHandler, dest, relayInfo, true, peerLog)
			if err != nil {
				return nil, err
			}
			encTunnel, err := wrapClientEncryptedStream(rawConn, cfg.PubKey)
			if err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if dc, ok := rawConn.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dc.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			}
			handshakeErr := doClientSecondaryHandshake(encTunnel, assignedUUID, cfg.UserUUID, cfg.RouteID)
			if dc, ok := rawConn.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dc.SetDeadline(time.Time{})
			}
			if handshakeErr != nil {
				_ = rawConn.Close()
				// Server no longer knows about this session: trigger a full primary reconnect
				// instead of endlessly retrying secondary handshakes that will keep failing.
				if handshakeErr.Error() == "session not found" || handshakeErr.Error() == "session mismatch" {
					return nil, fmt.Errorf("%w: %s", ErrNeedFullReconnect, handshakeErr.Error())
				}
				return nil, handshakeErr
			}
			if cfg.Encryption == "full" {
				return encTunnel, nil
			}
			return encTunnel.Underlying(), nil
		}
	}

	peerConn := NewPeerConn()
	if err := peerConn.AddPeer(conn0, makePeerReconnectFn(0)); err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return err
	}

	// KCP transport over PeerConn.
	kcpHandler := &transportpkg.KCPHandler{}
	muxTransport, err := kcpHandler.WrapPacketConn(peerConn)
	if err != nil {
		_ = peerConn.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("kcp setup: %w", err)
	}

	// Plain VPNMux - no auth or encryption at this layer; handled per-peer above.
	muxClient, err := NewVPNMuxClient(muxTransport)
	if err != nil {
		_ = muxTransport.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return err
	}

	// Atomically swap in new session state.
	D.mu.Lock()
	D.cancel = cancel
	D.proto = protoHandler
	D.platform = platformHandler
	D.muxClient = muxClient
	D.peerConn = peerConn
	D.sessionUUID = sessionUUIDStr
	D.mu.Unlock()

	// Tear down previous session (best-effort).
	if oldCancel != nil {
		oldCancel()
	}
	if oldPeerConn != nil {
		_ = oldPeerConn.Close()
	}
	if oldPlatform != nil {
		_ = oldPlatform.Close()
	}
	if oldMux != nil {
		_ = oldMux.Close()
	}

	// fullReconnect triggers a fresh primary session with exponential backoff.
	// Only one trigger runs at a time; additional calls while reconnect is in progress are dropped.
	var reconnectInProgress atomic.Bool
	fullReconnect := func() {
		if reconnectInProgress.CompareAndSwap(false, true) {
			go func() {
				defer reconnectInProgress.Store(false)
				D.reconnecting.Store(true)
				defer D.reconnecting.Store(false)
				delay := fullReconnectInit
				for {
					if err := D.connectClientSession(); err == nil {
						return
					} else {
						slog.Warn("full reconnect failed, retrying", "delay", delay, "error", err)
					}
					D.mu.Lock()
					ctx := D.reconnectCtx
					D.mu.Unlock()
					if ctx == nil {
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(delay):
					}
					delay *= 2
					if delay > fullReconnectMax {
						delay = fullReconnectMax
					}
				}
			}()
		}
	}

	// Register on peerConn so per-peer loops can escalate ErrNeedFullReconnect.
	peerConn.SetOnFullReconnect(fullReconnect)

	// Watch the mux session independently: if VPNMux dies (ping timeout or Disconnect
	// from server) without the underlying DTLS connections failing, nothing else would
	// notice. We detect it here and kick off a full reconnect.
	watchedMux := muxClient
	go func() {
		select {
		case <-watchedMux.Done():
			D.mu.Lock()
			isCurrentMux := D.muxClient == watchedMux
			D.mu.Unlock()
			if isCurrentMux {
				slog.Info("vpnmux session died, triggering full reconnect")
				fullReconnect()
			}
		case <-watchCtx.Done():
			// New session replaced this one, or handler is being torn down.
		}
	}()

	// Launch additional peers concurrently after the primary session is live.
	numPeers := cfg.Peers
	if numPeers < 1 {
		numPeers = 1
	}
	for i := 1; i < numPeers; i++ {
		peerIdx := i
		reconnFn := makePeerReconnectFn(peerIdx)
		go func() {
			delay := peerReconnectInit
			for {
				conn, err := reconnFn(peerConn.ctx)
				if err == nil {
					if addErr := peerConn.AddPeer(conn, reconnFn); addErr != nil {
						slog.Warn("peer add failed", "peer_idx", peerIdx, "error", addErr)
					}
					return
				}
				if errors.Is(err, ErrNeedFullReconnect) {
					slog.Info("peer needs full session reconnect during init", "peer_idx", peerIdx)
					peerConn.mu.RLock()
					fn := peerConn.onFullReconnect
					peerConn.mu.RUnlock()
					if fn != nil {
						fn()
					}
					return
				}
				slog.Warn("peer handshake failed", "peer_idx", peerIdx, "delay", delay, "error", err)
				if errors.Is(err, protocol.ErrQuotaReached) {
					delay = peerQuotaBackoff
				}
				select {
				case <-peerConn.ctx.Done():
					return
				case <-time.After(delay):
				}
				delay *= 2
				if delay > peerReconnectMax {
					delay = peerReconnectMax
				}
			}
		}()
	}

	slog.Info("relay client session connected", "session_uuid", sessionUUIDStr, "peers", numPeers)
	return nil
}

// AcceptNewClients emits authenticated relay sessions accepted by the underlying protocol.
func (D *RelayHandler) AcceptNewClients(ctx context.Context) <-chan ServerClient {
	out := make(chan ServerClient)

	D.mu.Lock()
	protoHandler := D.proto
	serverCfg := D.serverConfig
	D.mu.Unlock()

	go func() {
		defer close(out)

		if protoHandler == nil || serverCfg == nil {
			return
		}

		for client := range protoHandler.AcceptNewClients(ctx) {
			client := client
			go func() {
				if err := D.handleIncomingPeer(ctx, client, serverCfg, out); err != nil {
					slog.Warn("relay peer handling failed", "addr", client.Address, "error", err)
				}
			}()
		}
	}()

	return out
}

// handleIncomingPeer dispatches an incoming peer to the primary or secondary handler.
func (D *RelayHandler) handleIncomingPeer(
	ctx context.Context,
	client protocol.ServerClient,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	// Deadline covers the full per-peer KEM exchange + hello.
	if dc, ok := client.IO.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Now().Add(relayHandshakeTimeout))
	}

	// Every peer gets its own EncryptedTunnel with an independent KEM-derived key.
	encTunnel, err := wrapServerEncryptedStream(client.IO, serverCfg.PrivKey)
	if err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("peer encryption setup: %w", err)
	}

	// Read hello type byte (sent inside the encrypted tunnel).
	typeBuf := make([]byte, 1)
	if _, err := common.ReadFullRetry(encTunnel, typeBuf); err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("read hello type: %w", err)
	}

	switch typeBuf[0] {
	case relayHelloTypePrimary:
		return D.handlePrimaryPeer(ctx, client, encTunnel, serverCfg, out)
	case relayHelloTypeSecondary:
		return D.handleSecondaryPeer(client, encTunnel)
	default:
		_ = client.IO.Close()
		return fmt.Errorf("unknown hello type %d", typeBuf[0])
	}
}

// handlePrimaryPeer establishes the primary session (KCP → VPNMux) for a new client.
func (D *RelayHandler) handlePrimaryPeer(
	ctx context.Context,
	client protocol.ServerClient,
	encTunnel *EncryptedTunnel,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	configURL, err := readPrimaryHello(encTunnel)
	if err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("read primary hello: %w", err)
	}

	clientCfg, user, route, err := validateRelayConfigURL(*serverCfg, configURL)
	if err != nil {
		_ = writePrimaryAck(encTunnel, [16]byte{}, err.Error())
		_ = client.IO.Close()
		return err
	}

	sessionID := uuid.New()
	var sessionUUIDBin [16]byte
	copy(sessionUUIDBin[:], sessionID[:])

	if err := writePrimaryAck(encTunnel, sessionUUIDBin, ""); err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("write primary ack: %w", err)
	}

	// Clear deadline after handshake.
	if dc, ok := client.IO.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Time{})
	}

	sessionUUIDStr := sessionID.String()
	slog.Info("relay handshake started", "addr", client.Address)

	peerConn := NewPeerConn()
	peerConn.SetLogger(slog.With("session_uuid", sessionUUIDStr))
	newSess := &relayServerSession{
		peerConn: peerConn,
		userUUID: clientCfg.UserUUID,
		routeID:  clientCfg.RouteID,
		fullEnc:  clientCfg.Encryption == "full",
	}

	actual, loaded := D.sessions.LoadOrStore(sessionUUIDStr, newSess)
	if loaded {
		// UUID collision (extremely unlikely) - join the existing session.
		existSess := actual.(*relayServerSession)
		var conn io.ReadWriteCloser
		if existSess.fullEnc {
			conn = encTunnel
		} else {
			conn = encTunnel.Underlying()
		}
		_ = existSess.peerConn.AddPeer(conn, nil)
		return nil
	}
	defer D.sessions.Delete(sessionUUIDStr)

	var peer0 io.ReadWriteCloser
	if clientCfg.Encryption == "full" {
		peer0 = encTunnel
	} else {
		peer0 = encTunnel.Underlying()
	}
	_ = peerConn.AddPeer(peer0, nil)

	kcpHandler := &transportpkg.KCPHandler{}
	kcpTransport, err := kcpHandler.WrapPacketConn(peerConn)
	if err != nil {
		_ = peerConn.Close()
		return fmt.Errorf("kcp setup: %w", err)
	}
	defer func() { _ = kcpTransport.Close() }()

	muxServer, err := NewVPNMuxServer(kcpTransport)
	if err != nil {
		return fmt.Errorf("vpnmux setup: %w", err)
	}
	defer func() { _ = muxServer.Close() }()
	muxServer.SetSessionUUID(sessionUUIDStr)

	// When all peers disconnect, forcibly close the mux so AcceptChannels unblocks immediately.
	peerConn.SetOnAllPeersGone(func() { _ = muxServer.Close() })

	slog.Info("relay handshake completed", "addr", client.Address, "session_uuid", sessionUUIDStr, "user_uuid", clientCfg.UserUUID, "route_id", clientCfg.RouteID)

	for channel := range muxServer.AcceptChannels(ctx) {
		var stream io.ReadWriteCloser = channel.Stream
		if route.Socket == "udp" {
			stream = newFramedUDPStream(channel.Stream)
		}
		select {
		case out <- ServerClient{
			Address:        client.Address,
			IO:             stream,
			Config:         clientCfg,
			User:           user,
			Route:          route,
			SessionUUID:    fmt.Sprintf("%s:%d", sessionUUIDStr, channel.ID),
			CloseRequested: channel.CloseRequested,
		}:
		case <-ctx.Done():
			_ = channel.Stream.Close()
			return nil
		}
	}
	// If the server context was canceled (graceful shutdown), notify the client before
	// the deferred Close() tears down the session.
	select {
	case <-ctx.Done():
		_ = muxServer.SendDisconnect()
	default:
	}
	return nil
}

// handleSecondaryPeer attaches an incoming secondary connection to an existing session.
func (D *RelayHandler) handleSecondaryPeer(
	client protocol.ServerClient,
	encTunnel *EncryptedTunnel,
) error {
	sessionUUIDBin, userUUID, routeID, err := readSecondaryHello(encTunnel)
	if err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("read secondary hello: %w", err)
	}

	sessionUUIDStr := uuid.UUID(sessionUUIDBin).String()

	existing, loaded := D.sessions.Load(sessionUUIDStr)
	if !loaded {
		_ = writeSecondaryAck(encTunnel, "session not found")
		_ = client.IO.Close()
		return fmt.Errorf("secondary peer: session %s not found", sessionUUIDStr)
	}

	sess := existing.(*relayServerSession)

	// Validate user UUID and route ID to prevent unauthorized peer injection.
	if sess.userUUID != userUUID || sess.routeID != routeID {
		_ = writeSecondaryAck(encTunnel, "session mismatch")
		_ = client.IO.Close()
		return fmt.Errorf("secondary peer: session mismatch for %s", sessionUUIDStr)
	}

	if err := writeSecondaryAck(encTunnel, ""); err != nil {
		_ = client.IO.Close()
		return fmt.Errorf("write secondary ack: %w", err)
	}

	// Clear deadline.
	if dc, ok := client.IO.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Time{})
	}

	var conn io.ReadWriteCloser
	if sess.fullEnc {
		conn = encTunnel
	} else {
		conn = encTunnel.Underlying()
	}

	if err := sess.peerConn.AddPeer(conn, nil); err != nil {
		_ = client.IO.Close()
		return err
	}

	slog.Debug("relay secondary peer joined session", "session_uuid", sessionUUIDStr, "addr", client.Address)
	return nil
}

// monitorRelayPlatform drains signaling events without tearing down the data session.
func monitorRelayPlatform(ctx context.Context, events <-chan platformpkg.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				slog.Debug("relay signaling monitor stopped: event stream closed")
				return
			}
			if event.Type == platformpkg.EventCallEnded {
				slog.Debug("relay signaling reported call ended", "metadata", event.Metadata)
			}
		}
	}
}

// validateRelayConfigURL parses the client config URL and authorizes access to the requested route.
func validateRelayConfigURL(serverCfg config.ServerConfig, configURL string) (*config.ClientConfig, *config.User, *config.Route, error) {
	clientCfg, err := config.NewClientConfigFromURL(configURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse client config url: %w", err)
	}

	if common.IsNullOrWhiteSpace(clientCfg.UserUUID) {
		return nil, nil, nil, errors.New("relay handshake missing user_uuid")
	}
	if common.IsNullOrWhiteSpace(clientCfg.RouteID) {
		return nil, nil, nil, errors.New("relay handshake missing route_id")
	}
	if clientCfg.Type != "relay" {
		return nil, nil, nil, fmt.Errorf("unexpected connection type %q", clientCfg.Type)
	}

	switch clientCfg.Encryption {
	case "handshake", "full":
	default:
		return nil, nil, nil, fmt.Errorf("invalid relay encryption mode %q", clientCfg.Encryption)
	}

	user, err := serverCfg.GetUser(clientCfg.UserUUID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve user: %w", err)
	}

	route, err := serverCfg.GetRoute(clientCfg.RouteID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve route: %w", err)
	}

	isAllowed := false
	for _, routeID := range user.AllowedRoutes {
		if routeID == route.ID {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		return nil, nil, nil, fmt.Errorf("user %s is not authorized for route %s", user.UUID, route.ID)
	}

	if route.Socket != "tcp" && route.Socket != "udp" {
		return nil, nil, nil, fmt.Errorf("route %s has invalid socket type %q", route.ID, route.Socket)
	}

	return clientCfg, user, route, nil
}

// writePrimaryHello encodes and sends the primary hello payload.
func writePrimaryHello(enc io.Writer, configURL string) error {
	configBytes := []byte(configURL)
	buf := make([]byte, 0, 1+4+len(configBytes))
	buf = append(buf, relayHandshakeVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(configBytes)))
	buf = append(buf, configBytes...)
	if err := common.WriteFullRetry(enc, buf); err != nil {
		return fmt.Errorf("write primary hello: %w", err)
	}
	return nil
}

// readPrimaryHello decodes the primary hello payload.
func readPrimaryHello(enc io.Reader) (string, error) {
	header := make([]byte, 5) // version(1) + configLen(4)
	if _, err := common.ReadFullRetry(enc, header); err != nil {
		return "", fmt.Errorf("read primary hello header: %w", err)
	}
	if header[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported primary hello version %d", header[0])
	}
	configLen := binary.BigEndian.Uint32(header[1:5])
	if configLen == 0 {
		return "", errors.New("primary hello: empty config URL")
	}
	configBytes := make([]byte, configLen)
	if _, err := common.ReadFullRetry(enc, configBytes); err != nil {
		return "", fmt.Errorf("read primary hello config: %w", err)
	}
	return string(configBytes), nil
}

// writeSecondaryHello encodes and sends the secondary hello payload.
func writeSecondaryHello(enc io.Writer, sessionUUID [16]byte, userUUID, routeID string) error {
	userBytes := []byte(userUUID)
	routeBytes := []byte(routeID)
	buf := make([]byte, 0, 1+16+2+len(userBytes)+2+len(routeBytes))
	buf = append(buf, relayHandshakeVersion)
	buf = append(buf, sessionUUID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(userBytes)))
	buf = append(buf, userBytes...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(routeBytes)))
	buf = append(buf, routeBytes...)
	if err := common.WriteFullRetry(enc, buf); err != nil {
		return fmt.Errorf("write secondary hello: %w", err)
	}
	return nil
}

// readSecondaryHello decodes the secondary hello payload.
func readSecondaryHello(enc io.Reader) ([16]byte, string, string, error) {
	header := make([]byte, 19) // version(1) + uuid(16) + userUUIDLen(2)
	if _, err := common.ReadFullRetry(enc, header); err != nil {
		return [16]byte{}, "", "", fmt.Errorf("read secondary hello header: %w", err)
	}
	if header[0] != relayHandshakeVersion {
		return [16]byte{}, "", "", fmt.Errorf("unsupported secondary hello version %d", header[0])
	}
	var sessionUUID [16]byte
	copy(sessionUUID[:], header[1:17])
	userLen := binary.BigEndian.Uint16(header[17:19])
	userBytes := make([]byte, userLen)
	if _, err := common.ReadFullRetry(enc, userBytes); err != nil {
		return [16]byte{}, "", "", fmt.Errorf("read secondary hello user uuid: %w", err)
	}
	routeLenBuf := make([]byte, 2)
	if _, err := common.ReadFullRetry(enc, routeLenBuf); err != nil {
		return [16]byte{}, "", "", fmt.Errorf("read secondary hello route len: %w", err)
	}
	routeLen := binary.BigEndian.Uint16(routeLenBuf)
	routeBytes := make([]byte, routeLen)
	if _, err := common.ReadFullRetry(enc, routeBytes); err != nil {
		return [16]byte{}, "", "", fmt.Errorf("read secondary hello route id: %w", err)
	}
	return sessionUUID, string(userBytes), string(routeBytes), nil
}

// writePrimaryAck encodes and sends the primary ack (includes session UUID on success).
func writePrimaryAck(enc io.Writer, sessionUUID [16]byte, errMsg string) error {
	if errMsg == "" {
		buf := make([]byte, 0, 1+1+16)
		buf = append(buf, relayHandshakeVersion, relayAckOK)
		buf = append(buf, sessionUUID[:]...)
		if err := common.WriteFullRetry(enc, buf); err != nil {
			return fmt.Errorf("write primary ack: %w", err)
		}
		return nil
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	if err := common.WriteFullRetry(enc, buf); err != nil {
		return fmt.Errorf("write primary ack error: %w", err)
	}
	return nil
}

// readPrimaryAck decodes the primary ack, returning the server-assigned session UUID.
func readPrimaryAck(enc io.Reader) ([16]byte, string, error) {
	header := make([]byte, 2) // version(1) + status(1)
	if _, err := common.ReadFullRetry(enc, header); err != nil {
		return [16]byte{}, "", fmt.Errorf("read primary ack header: %w", err)
	}
	if header[0] != relayHandshakeVersion {
		return [16]byte{}, "", fmt.Errorf("unsupported primary ack version %d", header[0])
	}
	if header[1] == relayAckOK {
		sessionUUIDBin := make([]byte, 16)
		if _, err := common.ReadFullRetry(enc, sessionUUIDBin); err != nil {
			return [16]byte{}, "", fmt.Errorf("read primary ack session uuid: %w", err)
		}
		var sessionUUID [16]byte
		copy(sessionUUID[:], sessionUUIDBin)
		return sessionUUID, "", nil
	}
	errLenBuf := make([]byte, 2)
	if _, err := common.ReadFullRetry(enc, errLenBuf); err != nil {
		return [16]byte{}, "", fmt.Errorf("read primary ack error len: %w", err)
	}
	errLen := binary.BigEndian.Uint16(errLenBuf)
	errBytes := make([]byte, errLen)
	if _, err := common.ReadFullRetry(enc, errBytes); err != nil {
		return [16]byte{}, "", fmt.Errorf("read primary ack error msg: %w", err)
	}
	return [16]byte{}, string(errBytes), nil
}

// writeSecondaryAck encodes and sends the secondary ack.
func writeSecondaryAck(enc io.Writer, errMsg string) error {
	if errMsg == "" {
		buf := []byte{relayHandshakeVersion, relayAckOK}
		if err := common.WriteFullRetry(enc, buf); err != nil {
			return fmt.Errorf("write secondary ack: %w", err)
		}
		return nil
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	if err := common.WriteFullRetry(enc, buf); err != nil {
		return fmt.Errorf("write secondary ack error: %w", err)
	}
	return nil
}

// readSecondaryAck decodes the secondary ack, returning a non-empty error message on failure.
func readSecondaryAck(enc io.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := common.ReadFullRetry(enc, header); err != nil {
		return "", fmt.Errorf("read secondary ack header: %w", err)
	}
	if header[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported secondary ack version %d", header[0])
	}
	if header[1] == relayAckOK {
		return "", nil
	}
	errLenBuf := make([]byte, 2)
	if _, err := common.ReadFullRetry(enc, errLenBuf); err != nil {
		return "", fmt.Errorf("read secondary ack error len: %w", err)
	}
	errLen := binary.BigEndian.Uint16(errLenBuf)
	errBytes := make([]byte, errLen)
	if _, err := common.ReadFullRetry(enc, errBytes); err != nil {
		return "", fmt.Errorf("read secondary ack error msg: %w", err)
	}
	return string(errBytes), nil
}

// doClientPrimaryHandshake sends the primary hello and receives the server-assigned session UUID.
func doClientPrimaryHandshake(encTunnel io.ReadWriteCloser, configURL string) ([16]byte, error) {
	if err := common.WriteFullRetry(encTunnel, []byte{relayHelloTypePrimary}); err != nil {
		return [16]byte{}, fmt.Errorf("write hello type: %w", err)
	}
	if err := writePrimaryHello(encTunnel, configURL); err != nil {
		return [16]byte{}, err
	}
	sessionUUID, errMsg, err := readPrimaryAck(encTunnel)
	if err != nil {
		return [16]byte{}, err
	}
	if errMsg != "" {
		return [16]byte{}, errors.New(errMsg)
	}
	return sessionUUID, nil
}

// doClientSecondaryHandshake sends the secondary hello and waits for ack.
func doClientSecondaryHandshake(encTunnel io.ReadWriteCloser, sessionUUID [16]byte, userUUID, routeID string) error {
	if err := common.WriteFullRetry(encTunnel, []byte{relayHelloTypeSecondary}); err != nil {
		return fmt.Errorf("write hello type: %w", err)
	}
	if err := writeSecondaryHello(encTunnel, sessionUUID, userUUID, routeID); err != nil {
		return err
	}
	errMsg, err := readSecondaryAck(encTunnel)
	if err != nil {
		return err
	}
	if errMsg != "" {
		return errors.New(errMsg)
	}
	return nil
}
