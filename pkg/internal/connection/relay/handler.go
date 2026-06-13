package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/internal/connection"
	"github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
	"github.com/theairblow/turnable/pkg/internal/transport"
)

const (
	relayHandshakeVersion byte = 3

	relayHelloTypePrimary   byte = 1
	relayHelloTypeSecondary byte = 2

	relayAckOK  byte = 0
	relayAckErr byte = 1

	relayHandshakeTimeout = 10 * time.Second

	fullReconnectInit = 5 * time.Second
	fullReconnectMax  = 30 * time.Second

	peerHandshakeRetryMax = 45 * time.Second
)

// ErrAckRejected is returned when the server sends an error ACK during handshake
type ErrAckRejected struct{ msg string }

func (e *ErrAckRejected) Error() string { return e.msg }

// Handler represent a relay connection handler
type Handler struct {
	running atomic.Bool

	// server-side
	serverConfig *ServerConfig
	provider     providers.Provider
	proto        protocol.Handler
	sessions     sync.Map

	// client-side
	platform  platform.Handler
	muxClient *connection.TinyMuxClient
	peerConn  *connection.PeerConn
	cancel    context.CancelFunc

	clientConfig    *ClientConfig
	sessionUUID     string
	reconnecting    atomic.Bool
	reconnectMu     sync.Mutex
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (D *Handler) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	D.log = log
}

// relayServerSession tracks a multi-peer server-side session
type relayServerSession struct {
	peerConn  *connection.PeerConn
	muxServer atomic.Pointer[connection.TinyMuxServer]
	userUUID  string
	routes    []providers.Route
	fullEnc   bool
}

// ID returns the unique ID of this handler
func (D *Handler) ID() string {
	return "relay"
}

// Start starts the server listener
func (D *Handler) Start(rawConfig config.Config, provider providers.Provider) error {
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

	cfg, ok := rawConfig.(ServerConfig)
	if !ok {
		return errors.New("invalid config instance")
	}

	handler, err := protocol.GetHandler(cfg.Proto)
	if err != nil {
		return err
	}

	if err := handler.Start(cfg.ListenAddr); err != nil {
		return err
	}

	D.serverConfig = &cfg
	D.provider = provider
	D.proto = handler
	success = true
	return nil
}

// Stop stops the relay-side protocol listener.
func (D *Handler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	protoHandler := D.proto
	D.serverConfig = nil
	D.proto = nil

	if protoHandler == nil {
		return nil
	}

	D.sessions.Range(func(_, val any) bool {
		sess := val.(*relayServerSession)
		if ms := sess.muxServer.Load(); ms != nil {
			_ = ms.Disconnect()
		}
		return true
	})

	time.Sleep(100 * time.Millisecond)

	return protoHandler.Stop()
}

// Connect connects to a remote server
func (D *Handler) Connect(rawConfig config.Config) error {
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

	cfg, ok := rawConfig.(ClientConfig)
	if !ok {
		return errors.New("invalid config instance")
	}

	if cfg.Proto == "none" {
		D.log.Warn("using no protocol is dangerous, please reconsider!")
	}

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())

	D.clientConfig = &cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel

	if err := D.connectClientSession(); err != nil {
		reconnectCancel()
		return err
	}

	success = true
	return nil
}

// OpenChannel opens a new logical data channel
func (D *Handler) OpenChannel(routeIdx byte) (net.Conn, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.reconnecting.Load() {
		return nil, connection.ErrReconnecting
	}

	muxClient := D.muxClient

	if muxClient == nil {
		return nil, errors.New("relay: no active mux connection")
	}

	stream, err := muxClient.OpenChannel(routeIdx)
	if err != nil {
		if D.muxClient == muxClient {
			D.muxClient = nil
		}

		_ = muxClient.Close()
		return nil, fmt.Errorf("relay: mux channel open failed: %w", err)
	}

	cfg := D.clientConfig
	if cfg == nil {
		_ = stream.Close()
		return nil, errors.New("relay: no client config")
	}

	transportID := "none"
	if int(routeIdx) < len(cfg.Routes) {
		if t := cfg.Routes[routeIdx].Transport; t != "" {
			transportID = t
		}
	}

	handler, err := transport.GetHandler(transportID)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport setup: %w", err)
	}

	wrapped, err := handler.WrapClient(stream)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport wrap: %w", err)
	}

	return wrapped, nil
}

// Disconnect gracefully disconnects from the current remote server
func (D *Handler) Disconnect() error {
	if !D.running.CompareAndSwap(true, false) {
		return nil
	}

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

// Close forcibly closes the current remove server connection
func (D *Handler) Close() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

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

// AcceptClients accepts and emits new authenticated server clients
func (D *Handler) AcceptClients(ctx context.Context) (<-chan connection.ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}

	out := make(chan connection.ServerClient)
	protoHandler := D.proto
	serverCfg := D.serverConfig

	go func() {
		defer close(out)

		if protoHandler == nil || serverCfg == nil {
			return
		}

		clientCh, err := protoHandler.AcceptClients(ctx)
		if err != nil {
			D.log.Warn("accept clients failed", "error", err)
			return
		}

		for client := range clientCh {
			go func() {
				if err := D.handleIncomingPeer(ctx, client, serverCfg, out); err != nil {
					D.log.Warn("relay peer handling failed", "addr", client.Address, "error", err)
				}
			}()
		}
	}()

	return out, nil
}

// relayWatchPlatform watches platform signaling events
func relayWatchPlatform(ctx context.Context, events <-chan platform.Event, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				log.Debug("relay signaling monitor stopped: event stream closed")
				return
			}
			if event.Type == platform.EventCallEnded {
				log.Debug("relay signaling reported call ended", "metadata", event.Metadata)
			}
		}
	}
}
