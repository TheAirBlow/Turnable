package connection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	platformpkg "github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
)

func init() {
	Handlers.Register(&DirectHandler{})
}

// DirectHandler establishes a direct raw UDP connection to a gateway
type DirectHandler struct {
	running atomic.Bool

	cancel          context.CancelFunc
	peerConn        *PeerConn
	clientConfig    *config.ClientConfig
	reconnecting    atomic.Bool
	reconnectMu     sync.Mutex
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (D *DirectHandler) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	D.log = log
}

// ID returns the unique ID of this handler
func (D *DirectHandler) ID() string { return "direct" }

// Start starts the server listener
func (D *DirectHandler) Start(_ config.ServerConfig) error {
	return errors.New("direct handler does not support server mode")
}

// Stop stops the server listener
func (D *DirectHandler) Stop() error {
	return errors.New("direct handler does not support server mode")
}

// AcceptClients accepts and emits new authenticated server clients
func (D *DirectHandler) AcceptClients(_ context.Context) (<-chan ServerClient, error) {
	return nil, errors.New("direct handler does not support server mode")
}

// Connect connects to a remote server
func (D *DirectHandler) Connect(cfg config.ClientConfig) error {
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

	if cfg.Type != D.ID() {
		return fmt.Errorf("invalid connection type %q, expected %q", cfg.Type, D.ID())
	}
	if len(cfg.Routes) != 1 {
		return errors.New("direct handler only supports one route")
	}
	if cfg.Routes[0].Socket != "udp" {
		return errors.New("direct handler only supports UDP")
	}
	if cfg.Routes[0].Transport != "none" {
		return errors.New("direct handler does not support any transports")
	}
	if cfg.Proto != "none" {
		return errors.New("direct handler only supports the 'none' protocol")
	}
	if common.IsNullOrWhiteSpace(cfg.Gateway) {
		return errors.New("direct handler requires a gateway address")
	}

	D.log.Warn("using a direct connection is dangerous, please reconsider!")

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
	D.clientConfig = &cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel

	if err := D.connectSession(); err != nil {
		reconnectCancel()
		return err
	}

	success = true
	return nil
}

// connectSession establishes all peer connections and initializes the PeerConn
func (D *DirectHandler) connectSession() error {
	D.reconnectMu.Lock()
	defer D.reconnectMu.Unlock()

	if D.cancel != nil {
		D.cancel()
		D.cancel = nil
	}
	if D.peerConn != nil {
		_ = D.peerConn.Close()
		D.peerConn = nil
	}

	cfg := D.clientConfig
	if cfg == nil {
		return errors.New("direct: no client config")
	}

	platformHandler, err := platformpkg.GetHandler(cfg.PlatformID)
	if err != nil {
		return err
	}
	if err := platformHandler.Authorize(cfg.CallID, cfg.Username); err != nil {
		return err
	}

	if os.Getenv("QUIT_AFTER_AUTH") == "1" {
		D.log.Info("QUIT_AFTER_AUTH set, quitting...")
		os.Exit(0)
	}

	sessionCtx, sessionCancel := context.WithCancel(D.reconnectCtx)
	events := platformHandler.WatchEvents(sessionCtx)

	if err := platformHandler.Connect(); err != nil {
		sessionCancel()
		_ = platformHandler.Close()
		return err
	}

	if !protocol.HandlerExists(cfg.Proto) {
		sessionCancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("protocol handler %s not found", cfg.Proto)
	}

	turnInfo := platformHandler.GetTURNInfo()
	dest, err := common.ResolveUDPAddr(cfg.Gateway)
	if err != nil {
		sessionCancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("invalid relay gateway %q: %w", cfg.Gateway, err)
	}

	relayInfo := protocol.RelayInfo{
		Address:   turnInfo.Address,
		Addresses: append([]string(nil), turnInfo.Addresses...),
		Username:  turnInfo.Username,
		Password:  turnInfo.Password,
	}

	go directWatchPlatform(sessionCtx, events, D.log)

	numPeers := cfg.Peers
	if numPeers < 1 {
		numPeers = 1
	}

	fullReconnect := func(reason string) {
		if !D.reconnecting.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer D.reconnecting.Store(false)
			delay := fullReconnectInit
			D.log.Info("direct: starting full reconnect", "reason", reason, "delay", delay)
			select {
			case <-sessionCtx.Done():
				return
			case <-time.After(delay):
			}
			for {
				if err := D.connectSession(); err == nil {
					return
				} else {
					D.log.Warn("direct: full reconnect failed", "delay", delay, "error", err)
				}
				rCtx := D.reconnectCtx
				if rCtx == nil {
					return
				}
				select {
				case <-rCtx.Done():
					return
				case <-time.After(delay):
				}
				delay = min(delay*2, fullReconnectMax)
			}
		}()
	}

	dial := func(idx int, dialCtx context.Context) (net.Conn, error) {
		h, _ := protocol.GetHandler("none")
		h.SetLogger(D.log.With("peer_idx", idx))
		connCtx, connCancel := context.WithTimeout(dialCtx, 5*time.Second)
		defer connCancel()
		return h.Connect(connCtx, dest, relayInfo, true)
	}

	peerConn := NewPeerConn(sessionCtx)
	peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

	for idx := 0; idx < numPeers; idx++ {
		go func() {
			delay := peerReconnectInit
			for {
				raw, err := dial(idx, sessionCtx)
				if err != nil {
					if sessionCtx.Err() != nil {
						return
					}
					if errors.Is(err, protocol.ErrQuotaReached) {
						D.log.Warn("peer quota reached, backing off", "peer_idx", idx, "delay", peerQuotaBackoff)
						delay = peerQuotaBackoff
					}

					D.log.Warn("peer connect failed", "peer_idx", idx, "error", err, "delay", delay)
					select {
					case <-sessionCtx.Done():
						return
					case <-time.After(delay):
					}

					delay = min(delay*2, peerReconnectMax)
					continue
				}

				_ = peerConn.AddPeer(raw, func(peerCtx context.Context) (net.Conn, error) {
					return dial(idx, peerCtx)
				})
				break
			}
		}()
	}

	D.cancel = sessionCancel
	D.peerConn = peerConn
	D.log.Info("direct session connected", "gateway", cfg.Gateway, "peers", numPeers)
	return nil
}

// OpenChannel opens a new logical data channel
func (D *DirectHandler) OpenChannel(_ byte) (net.Conn, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.reconnecting.Load() {
		return nil, ErrReconnecting
	}
	if D.peerConn == nil {
		return nil, errors.New("direct: no active connection")
	}
	return D.peerConn, nil
}

// Disconnect gracefully tears down all peer connections
func (D *DirectHandler) Disconnect() error {
	if !D.running.CompareAndSwap(true, false) {
		return nil
	}
	cancel := D.cancel
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	D.cancel = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil

	if cancel != nil {
		cancel()
	}
	if reconnectCancel != nil {
		reconnectCancel()
	}
	if peerConn != nil {
		return peerConn.Close()
	}
	return nil
}

// Close forcibly closes the connection
func (D *DirectHandler) Close() error {
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
