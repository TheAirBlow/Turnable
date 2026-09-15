package direct

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
	platformpkg "github.com/theairblow/turnable/pkg/platform"
)

// Handler establishes a direct raw UDP connection to a gateway
type Handler struct {
	running atomic.Bool

	cancel          context.CancelFunc
	peerConn        *connection.PeerConn
	clientConfig    *ClientConfig
	reconnecting    atomic.Bool
	reconnectMu     sync.Mutex
	stateMu         sync.RWMutex
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc
	events          *connection.EventStream

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (D *Handler) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	D.log = log
}

// ID returns the unique ID of this handler
func (D *Handler) ID() string { return "direct" }

// Start starts the server listener
func (D *Handler) Start(_ config.Config, _ providers.Provider) error {
	return errors.New("direct handler does not support server mode")
}

// Stop stops the server listener
func (D *Handler) Stop() error {
	return errors.New("direct handler does not support server mode")
}

// AcceptClients accepts and emits new authenticated server clients
func (D *Handler) AcceptClients(_ context.Context) (<-chan connection.ServerClient, error) {
	return nil, errors.New("direct handler does not support server mode")
}

// Connect connects to a remote server, returning a channel of connectivity transitions
func (D *Handler) Connect(rawConfig config.Config) (<-chan connection.ConnectEvent, error) {
	if !D.running.CompareAndSwap(false, true) {
		return nil, errors.New("already running")
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

	cfg, ok := rawConfig.(*ClientConfig)
	if !ok {
		return nil, errors.New("invalid config instance")
	}

	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	D.log.Warn("using a direct connection is dangerous, please reconsider!")

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
	events := connection.NewEventStream()
	D.stateMu.Lock()
	D.clientConfig = cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel
	D.events = events
	D.stateMu.Unlock()

	connection.RunReconnectLoop(reconnectCtx, D.log, &D.reconnecting, events, "initial connect", D.connectSession)

	success = true
	return events.Chan(), nil
}

// OpenChannel opens a new logical data channel
func (D *Handler) OpenChannel(_ byte) (net.Conn, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.reconnecting.Load() {
		return nil, connection.ErrReconnecting
	}
	D.stateMu.RLock()
	peerConn := D.peerConn
	D.stateMu.RUnlock()
	if peerConn == nil {
		return nil, errors.New("direct: no active connection")
	}
	return peerConn, nil
}

// Disconnect gracefully tears down all peer connections
func (D *Handler) Disconnect() error {
	if !D.running.CompareAndSwap(true, false) {
		return nil
	}
	D.stateMu.Lock()
	cancel := D.cancel
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	events := D.events
	D.cancel = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.events = nil
	D.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if reconnectCancel != nil {
		reconnectCancel()
	}
	if events != nil {
		events.Close()
	}
	if peerConn != nil {
		return peerConn.Close()
	}
	return nil
}

// Close forcibly closes the connection
func (D *Handler) Close() error {
	return D.Disconnect()
}

// directWatchPlatform watches platform signaling events
func directWatchPlatform(ctx context.Context, events <-chan platformpkg.Event, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				log.Debug("direct signaling monitor stopped: event stream closed")
				return
			}
			if event.Type == platformpkg.EventCallEnded {
				log.Debug("direct signaling reported call ended", "metadata", event.Metadata)
			}
		}
	}
}
