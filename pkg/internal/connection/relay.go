package connection

import (
	"context"
	"crypto/rand"
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
	muxClient *TinyMuxClient
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
func (D *RelayHandler) Connect(cfg config.ClientConfig) error {
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

// OpenChannel opens a new tinymux data channel, wrapping with transport for TCP
func (D *RelayHandler) OpenChannel(socketType string) (net.Conn, error) {
	flowConn, err := D.openChannel()
	if err != nil {
		return nil, err
	}
	if strings.ToLower(socketType) == "tcp" {
		D.mu.Lock()
		cfg := D.clientConfig
		D.mu.Unlock()
		if cfg == nil {
			_ = flowConn.Close()
			return nil, errors.New("relay: no client config")
		}
		handler, err := transportpkg.GetHandler(cfg.Transport)
		if err != nil {
			_ = flowConn.Close()
			return nil, fmt.Errorf("relay: transport setup: %w", err)
		}
		wrapped, err := handler.WrapClient(flowConn)
		if err != nil {
			_ = flowConn.Close()
			return nil, fmt.Errorf("relay: transport wrap: %w", err)
		}
		return wrapped, nil
	}
	return flowConn, nil
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
			_ = muxClient.Disconnect()
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

// openChannel opens a new mux channel for data forwarding
func (D *RelayHandler) openChannel() (net.Conn, error) {
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

// connectClientSession establishes the platform, underlay, and tinymux session for the client.
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

	if !protocol.HandlerExists(cfg.Proto) {
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("protocol handler %s not found", cfg.Proto)
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

	// TODO: make all peers connect at the same time, and the first one that connects should become the primary
	handler0, _ := protocol.GetHandler(cfg.Proto)
	handler0.SetLogger(slog.With("peer_idx", 0))
	ctx, cancel := context.WithTimeout(watchCtx, 5*time.Second)
	defer cancel()

	rawConn0, err := handler0.Connect(ctx, dest, relayInfo, true)
	if err != nil {
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 connect: %w", err)
	}

	encTunnel0, err := wrapClientEncryptedConn(rawConn0, cfg.PubKey)
	if err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 encryption init: %w", err)
	}

	_ = rawConn0.SetDeadline(time.Now().Add(relayHandshakeTimeout))

	assignedUUID, err := doClientPrimaryHandshake(encTunnel0, cfg.ToURL(true))
	_ = rawConn0.SetDeadline(time.Time{})

	if err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("peer 0 handshake: %w", err)
	}

	sessionUUIDStr := uuid.UUID(assignedUUID).String()

	var conn0 net.Conn
	if cfg.Encryption == "full" {
		conn0 = encTunnel0
	} else {
		conn0 = encTunnel0.Underlying()
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

	// Reconnect factory - all peers (including peer 0) reconnect as secondary peers,
	// since the primary session (VPNMux) stays alive as long as ≥1 peer is connected.
	makePeerReconnectFn := func(peerIdx int) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			handler, _ := protocol.GetHandler(cfg.Proto)
			handler.SetLogger(slog.With("peer_idx", peerIdx))
			ctx, cancel := context.WithTimeout(watchCtx, 5*time.Second)
			defer cancel()

			rawConn, err := handler0.Connect(ctx, dest, relayInfo, true)
			if err != nil {
				return nil, err
			}
			encTunnel, err := wrapClientEncryptedConn(rawConn, cfg.PubKey)
			if err != nil {
				_ = rawConn.Close()
				return nil, err
			}

			_ = rawConn.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			handshakeErr := doClientSecondaryHandshake(encTunnel, assignedUUID, cfg.UserUUID, cfg.RouteID)
			_ = rawConn.SetDeadline(time.Time{})

			if handshakeErr != nil {
				_ = rawConn.Close()
				// Server no longer knows about this session: trigger a full primary reconnect
				// instead of endlessly retrying secondary handshakes that will keep failing.
				if handshakeErr.Error() == "session not found" || handshakeErr.Error() == "session mismatch" {
					fullReconnect()
					return nil, ErrPeerDone
				}
				return nil, handshakeErr
			}

			if cfg.Encryption == "full" {
				return encTunnel, nil
			}
			return encTunnel.Underlying(), nil
		}
	}

	peerConn := NewPeerConn(watchCtx)
	if err := peerConn.AddPeer(conn0, makePeerReconnectFn(0)); err != nil {
		_ = rawConn0.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return err
	}

	// VPNMux directly on PeerConn - transport is per-flow, not global.
	muxClient, err := NewTinyMuxClient(watchCtx, peerConn)
	if err != nil {
		_ = peerConn.Close()
		cancel()
		_ = platformHandler.Disconnect()
		return err
	}

	// Atomically swap in new session state.
	D.mu.Lock()
	D.cancel = cancel
	D.proto = handler0
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
				slog.Info("tinymux session died, triggering full reconnect")
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
				if errors.Is(err, ErrPeerDone) {
					// fullReconnect already triggered inside reconnFn.
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

// AcceptClients emits authenticated relay sessions accepted by the underlying protocol.
func (D *RelayHandler) AcceptClients(ctx context.Context) <-chan ServerClient {
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

		clientCh, err := protoHandler.AcceptClients(ctx)
		if err != nil {
			slog.Warn("accept clients failed", "error", err)
			return
		}

		for client := range clientCh {
			go func() {
				if err := D.handleIncomingPeer(ctx, client, serverCfg, out); err != nil {
					slog.Warn("relay peer handling failed", "addr", client.Address, "error", err)
				}
			}()
		}
	}()

	return out
}

// handleIncomingPeer dispatches an incoming peer to the primary or secondary handler
func (D *RelayHandler) handleIncomingPeer(
	ctx context.Context,
	client protocol.ServerClient,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	_ = client.Conn.SetDeadline(time.Now().Add(relayHandshakeTimeout))

	// Every peer gets its own EncryptedConn with an independent KEM-derived key.
	// TODO: fix resource leak
	encConn, err := wrapServerEncryptedConn(client.Conn, serverCfg.PrivKey)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("peer encryption setup: %w", err)
	}

	// Send a fresh 8-byte challenge so the client must echo it in the hello.
	// This binds the relay handshake to this specific connection and prevents replay.
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := encConn.Write(challenge[:]); err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("write challenge: %w", err)
	}

	// Read entire hello packet (type byte + challenge echo + payload) in one datagram read
	buf := make([]byte, 4096)
	n, err := encConn.Read(buf)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("read hello: %w", err)
	}
	if n < 9 {
		_ = client.Conn.Close()
		return errors.New("hello packet too short")
	}

	// Verify challenge echo (bytes 1-8)
	if [8]byte(buf[1:9]) != challenge {
		_ = client.Conn.Close()
		return errors.New("challenge mismatch: possible replay")
	}

	switch buf[0] {
	case relayHelloTypePrimary:
		return D.handlePrimaryPeer(ctx, client, encConn, buf[9:n], serverCfg, out)
	case relayHelloTypeSecondary:
		return D.handleSecondaryPeer(client, encConn, buf[9:n])
	default:
		_ = client.Conn.Close()
		return fmt.Errorf("unknown hello type %d", buf[0])
	}
}

// handlePrimaryPeer establishes the primary session (VPNMux) for a new client
func (D *RelayHandler) handlePrimaryPeer(
	ctx context.Context,
	client protocol.ServerClient,
	encConn *EncryptedConn,
	helloPayload []byte,
	serverCfg *config.ServerConfig,
	out chan<- ServerClient,
) error {
	configURL, err := parsePrimaryHello(helloPayload)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("parse primary hello: %w", err)
	}

	clientCfg, user, route, err := validateRelayConfigURL(*serverCfg, configURL)
	if err != nil {
		_ = writePrimaryAck(encConn, [16]byte{}, err.Error())
		_ = client.Conn.Close()
		return err
	}

	sessionID := uuid.New()
	var sessionUUIDBin [16]byte
	copy(sessionUUIDBin[:], sessionID[:])

	if err := writePrimaryAck(encConn, sessionUUIDBin, ""); err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("write primary ack: %w", err)
	}

	_ = client.Conn.SetDeadline(time.Time{})

	sessionUUIDStr := sessionID.String()
	slog.Info("relay handshake started", "addr", client.Address)

	peerConn := NewPeerConn(ctx)
	peerConn.SetLogger(slog.With("session_uuid", sessionUUIDStr))
	newSess := &relayServerSession{
		peerConn: peerConn,
		userUUID: clientCfg.UserUUID,
		routeID:  clientCfg.RouteID,
		fullEnc:  clientCfg.Encryption == "full",
	}

	actual, loaded := D.sessions.LoadOrStore(sessionUUIDStr, newSess)
	if loaded {
		existSess := actual.(*relayServerSession)
		var conn net.Conn
		if existSess.fullEnc {
			conn = encConn
		} else {
			conn = encConn.Underlying()
		}
		_ = existSess.peerConn.AddPeer(conn, nil)
		return nil
	}
	defer D.sessions.Delete(sessionUUIDStr)

	var peer0 net.Conn
	if clientCfg.Encryption == "full" {
		peer0 = encConn
	} else {
		peer0 = encConn.Underlying()
	}
	_ = peerConn.AddPeer(peer0, nil)

	// VPNMux directly on PeerConn - transport is per-flow.
	muxServer, err := NewTinyMuxServer(peerConn)
	if err != nil {
		_ = peerConn.Close()
		return fmt.Errorf("tinymux setup: %w", err)
	}
	defer func() { _ = muxServer.Close() }()

	// When all peers disconnect, forcibly close the mux so AcceptChannels unblocks immediately.
	peerConn.SetOnAllPeersGone(func() { _ = muxServer.Close() })

	// Per-flow transport handler for TCP routes.
	transportHandler, transportErr := transportpkg.GetHandler(route.Transport)
	if transportErr != nil {
		return fmt.Errorf("transport setup: %w", transportErr)
	}

	slog.Info("relay handshake completed", "addr", client.Address, "session_uuid", sessionUUIDStr, "user_uuid", clientCfg.UserUUID, "route_id", clientCfg.RouteID)

	for channel := range muxServer.AcceptChannels(ctx) {
		var conn net.Conn = channel.Conn
		if route.Socket == "tcp" {
			wrapped, wrapErr := transportHandler.WrapServer(channel.Conn)
			if wrapErr != nil {
				slog.Warn("transport wrap failed", "flow_id", channel.FlowID, "error", wrapErr)
				_ = channel.Conn.Close()
				continue
			}
			conn = wrapped
		}
		select {
		case out <- ServerClient{
			Address:     client.Address,
			Conn:        conn,
			Config:      clientCfg,
			User:        user,
			Route:       route,
			SessionUUID: fmt.Sprintf("%s:%d", sessionUUIDStr, channel.FlowID),
		}:
		case <-ctx.Done():
			_ = channel.Conn.Close()
			return nil
		}
	}
	select {
	case <-ctx.Done():
		_ = muxServer.Disconnect()
	default:
	}
	return nil
}

// handleSecondaryPeer attaches an incoming secondary connection to an existing session
func (D *RelayHandler) handleSecondaryPeer(
	client protocol.ServerClient,
	encConn *EncryptedConn,
	helloPayload []byte,
) error {
	sessionUUIDBin, userUUID, routeID, err := parseSecondaryHello(helloPayload)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("parse secondary hello: %w", err)
	}

	sessionUUIDStr := uuid.UUID(sessionUUIDBin).String()

	existing, loaded := D.sessions.Load(sessionUUIDStr)
	if !loaded {
		_ = writeSecondaryAck(encConn, "session not found")
		_ = client.Conn.Close()
		return fmt.Errorf("secondary peer: session %s not found", sessionUUIDStr)
	}

	sess := existing.(*relayServerSession)

	if sess.userUUID != userUUID || sess.routeID != routeID {
		_ = writeSecondaryAck(encConn, "session mismatch")
		_ = client.Conn.Close()
		return fmt.Errorf("secondary peer: session mismatch for %s", sessionUUIDStr)
	}

	if err := writeSecondaryAck(encConn, ""); err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("write secondary ack: %w", err)
	}

	_ = client.Conn.SetDeadline(time.Time{})

	var conn net.Conn
	if sess.fullEnc {
		conn = encConn
	} else {
		conn = encConn.Underlying()
	}

	if err := sess.peerConn.AddPeer(conn, nil); err != nil {
		_ = client.Conn.Close()
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

// writePrimaryHello sends hello_type + challenge_echo + version + configLen + config as a single packet
func writePrimaryHello(w io.Writer, challenge [8]byte, configURL string) error {
	configBytes := []byte(configURL)
	buf := make([]byte, 0, 1+8+1+4+len(configBytes))
	buf = append(buf, relayHelloTypePrimary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(configBytes)))
	buf = append(buf, configBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryHello parses the hello payload (after type byte is stripped)
func parsePrimaryHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("primary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported primary hello version %d", data[0])
	}
	configLen := binary.BigEndian.Uint32(data[1:5])
	if configLen == 0 {
		return "", errors.New("primary hello: empty config URL")
	}
	if len(data) < 5+int(configLen) {
		return "", errors.New("primary hello: truncated config")
	}
	return string(data[5 : 5+configLen]), nil
}

// writeSecondaryHello sends hello_type + challenge_echo + version + uuid + userLen + user + routeLen + route as a single packet
func writeSecondaryHello(w io.Writer, challenge [8]byte, sessionUUID [16]byte, userUUID, routeID string) error {
	userBytes := []byte(userUUID)
	routeBytes := []byte(routeID)
	buf := make([]byte, 0, 1+8+1+16+2+len(userBytes)+2+len(routeBytes))
	buf = append(buf, relayHelloTypeSecondary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = append(buf, sessionUUID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(userBytes)))
	buf = append(buf, userBytes...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(routeBytes)))
	buf = append(buf, routeBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryHello parses the secondary hello payload (after type byte is stripped)
func parseSecondaryHello(data []byte) ([16]byte, string, string, error) {
	if len(data) < 19 { // version(1) + uuid(16) + userLen(2)
		return [16]byte{}, "", "", errors.New("secondary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", "", fmt.Errorf("unsupported secondary hello version %d", data[0])
	}
	var sessionUUID [16]byte
	copy(sessionUUID[:], data[1:17])
	userLen := binary.BigEndian.Uint16(data[17:19])
	off := 19
	if len(data) < off+int(userLen)+2 {
		return [16]byte{}, "", "", errors.New("secondary hello: truncated user uuid")
	}
	userUUID := string(data[off : off+int(userLen)])
	off += int(userLen)
	routeLen := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if len(data) < off+int(routeLen) {
		return [16]byte{}, "", "", errors.New("secondary hello: truncated route id")
	}
	routeID := string(data[off : off+int(routeLen)])
	return sessionUUID, userUUID, routeID, nil
}

// writePrimaryAck sends version + status + [uuid | errLen + err] as a single packet
func writePrimaryAck(w io.Writer, sessionUUID [16]byte, errMsg string) error {
	if errMsg == "" {
		buf := make([]byte, 0, 1+1+16)
		buf = append(buf, relayHandshakeVersion, relayAckOK)
		buf = append(buf, sessionUUID[:]...)
		_, err := w.Write(buf)
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryAck parses a primary ack packet, returning session UUID and error message
func parsePrimaryAck(data []byte) ([16]byte, string, error) {
	if len(data) < 2 {
		return [16]byte{}, "", errors.New("primary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", fmt.Errorf("unsupported primary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		if len(data) < 18 {
			return [16]byte{}, "", errors.New("primary ack uuid too short")
		}
		var sessionUUID [16]byte
		copy(sessionUUID[:], data[2:18])
		return sessionUUID, "", nil
	}
	if len(data) < 4 {
		return [16]byte{}, "", errors.New("primary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return [16]byte{}, "", errors.New("primary ack error truncated")
	}
	return [16]byte{}, string(data[4 : 4+errLen]), nil
}

// writeSecondaryAck sends version + status + [errLen + err] as a single packet
func writeSecondaryAck(w io.Writer, errMsg string) error {
	if errMsg == "" {
		_, err := w.Write([]byte{relayHandshakeVersion, relayAckOK})
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryAck parses a secondary ack packet, returning error message on failure
func parseSecondaryAck(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("secondary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported secondary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		return "", nil
	}
	if len(data) < 4 {
		return "", errors.New("secondary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return "", errors.New("secondary ack error truncated")
	}
	return string(data[4 : 4+errLen]), nil
}

// doClientPrimaryHandshake reads the server challenge, sends primary hello, and reads the server-assigned session UUID
func doClientPrimaryHandshake(conn net.Conn, configURL string) ([16]byte, error) {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return [16]byte{}, fmt.Errorf("read challenge: %w", err)
	}
	if err := writePrimaryHello(conn, challenge, configURL); err != nil {
		return [16]byte{}, fmt.Errorf("write primary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return [16]byte{}, fmt.Errorf("read primary ack: %w", err)
	}
	sessionUUID, errMsg, err := parsePrimaryAck(buf[:n])
	if err != nil {
		return [16]byte{}, err
	}
	if errMsg != "" {
		return [16]byte{}, errors.New(errMsg)
	}
	return sessionUUID, nil
}

// doClientSecondaryHandshake reads the server challenge, sends secondary hello, and waits for ack
func doClientSecondaryHandshake(conn net.Conn, sessionUUID [16]byte, userUUID, routeID string) error {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if err := writeSecondaryHello(conn, challenge, sessionUUID, userUUID, routeID); err != nil {
		return fmt.Errorf("write secondary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read secondary ack: %w", err)
	}
	errMsg, err := parseSecondaryAck(buf[:n])
	if err != nil {
		return err
	}
	if errMsg != "" {
		return errors.New(errMsg)
	}
	return nil
}
