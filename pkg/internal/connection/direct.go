package connection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
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

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	if cfg.Type != D.ID() {
		return fmt.Errorf("invalid connection type %q, expected %q", cfg.Type, D.ID())
	}
	if cfg.Socket != "udp" {
		return errors.New("direct handler only supports UDP")
	}
	if cfg.Proto != "none" {
		return errors.New("direct handler only supports the 'none' protocol")
	}
	if common.IsNullOrWhiteSpace(cfg.Gateway) {
		return errors.New("direct handler requires a gateway address")
	}

	slog.Warn("using a direct connection is dangerous, please reconsider!")

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

	dest, err := net.ResolveUDPAddr("udp", cfg.Gateway)
	if err != nil {
		return fmt.Errorf("invalid gateway %q: %w", cfg.Gateway, err)
	}

	numPeers := cfg.Peers
	if numPeers < 1 {
		numPeers = 1
	}

	ctx, cancel := context.WithCancel(D.reconnectCtx)

	fullReconnect := func(reason string) {
		if !D.reconnecting.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer D.reconnecting.Store(false)
			delay := fullReconnectInit
			slog.Info("direct: starting full reconnect", "reason", reason, "delay", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			for {
				if err := D.connectSession(); err == nil {
					return
				} else {
					slog.Warn("direct: full reconnect failed", "delay", delay, "error", err)
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

	noneHandler, err := protocol.GetHandler("none")
	if err != nil {
		cancel()
		return fmt.Errorf("direct: none protocol not found: %w", err)
	}

	dial := func(dialCtx context.Context) (net.Conn, error) {
		connCtx, connCancel := context.WithTimeout(dialCtx, 5*time.Second)
		defer connCancel()
		return noneHandler.Connect(connCtx, dest, protocol.RelayInfo{}, false)
	}

	peerConn := NewPeerConn(ctx)
	peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

	for i := 0; i < numPeers; i++ {
		conn, err := dial(ctx)
		if err != nil {
			_ = peerConn.Close()
			cancel()
			return fmt.Errorf("direct: peer %d connect failed: %w", i, err)
		}
		_ = peerConn.AddPeer(conn, func(peerCtx context.Context) (net.Conn, error) {
			return dial(peerCtx)
		})
	}

	D.cancel = cancel
	D.peerConn = peerConn
	slog.Info("direct session connected", "gateway", cfg.Gateway, "peers", numPeers)
	return nil
}

// OpenChannel opens a new logical data channel
func (D *DirectHandler) OpenChannel() (net.Conn, error) {
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
