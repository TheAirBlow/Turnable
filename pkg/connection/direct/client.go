package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/connection"
	platformpkg "github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/protocol"
)

// connectSession establishes all peer connections and initializes the PeerConn
func (D *Handler) connectSession() error {
	D.reconnectMu.Lock()
	defer D.reconnectMu.Unlock()

	D.stateMu.Lock()
	oldCancel := D.cancel
	oldPeerConn := D.peerConn
	cfg := D.clientConfig
	reconnectCtx := D.reconnectCtx
	D.cancel = nil
	D.peerConn = nil
	D.stateMu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldPeerConn != nil {
		_ = oldPeerConn.Close()
	}
	if cfg == nil {
		return errors.New("direct: no client config")
	}
	if reconnectCtx == nil {
		return errors.New("direct: reconnect context is not available")
	}

	platformHandler, err := platformpkg.GetHandler(cfg.PlatformID)
	if err != nil {
		return err
	}

	success := false
	defer func() {
		if !success {
			_ = platformHandler.Close()
		}
	}()

	platCfg := platformHandler.GetConfig()
	if !platCfg.HasInsecureTURN {
		return fmt.Errorf("platform does not have an insecure TURN server")
	}

	if err := platformHandler.Authorize(cfg.CallID, common.GenerateUsername()); err != nil {
		return err
	}

	if os.Getenv("QUIT_AFTER_AUTH") == "1" {
		D.log.Info("QUIT_AFTER_AUTH set, quitting...")
		os.Exit(0)
	}

	sessionCtx, sessionCancel := context.WithCancel(reconnectCtx)
	events := platformHandler.WatchEvents(sessionCtx)
	defer func() {
		if !success {
			sessionCancel()
		}
	}()

	// TODO: platform signaling connection not yet necessary, handle this later
	/*if err := platformHandler.Connect(); err != nil {
		sessionCancel()
		_ = platformHandler.Close()
		return err
	}*/

	turnInfo := platformHandler.GetTURNInfo()
	dest, err := common.ResolveUDPAddr(cfg.Gateway)
	if err != nil {
		sessionCancel()
		_ = platformHandler.Disconnect()
		return fmt.Errorf("invalid relay gateway %q: %w", cfg.Gateway, err)
	}

	go directWatchPlatform(sessionCtx, events, D.log)

	numPeers := cfg.Peers
	if numPeers < 1 {
		numPeers = 1
	}

	maxPeers := platCfg.MaxTURNConnections * len(turnInfo)
	if numPeers > maxPeers {
		D.log.Warn("number of peers requested forcibly limited to maximum", "requested_peers", numPeers, "max_peers", maxPeers)
		numPeers = maxPeers
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
				D.stateMu.RLock()
				rCtx := D.reconnectCtx
				D.stateMu.RUnlock()
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

	turnServerIdx := 0
	turnConnCount := 0
	var turnMu sync.Mutex

	getTURNInfo := func() protocol.TURNInfo {
		turnMu.Lock()
		defer turnMu.Unlock()

		if turnConnCount >= platCfg.MaxTURNConnections && platCfg.MaxTURNConnections > 0 && len(turnInfo) > 1 && platCfg.HasSharedTURNLimits {
			turnServerIdx++
			if turnServerIdx >= len(turnInfo) {
				turnServerIdx = 0
			}
			turnConnCount = 0
		}
		turnConnCount++
		return turnInfo[turnServerIdx]
	}

	dialFn := func(dialCtx context.Context, idx int) (net.Conn, error) {
		h, _ := protocol.GetHandler("none")
		h.SetLogger(D.log.With("peer_idx", idx))
		connCtx, connCancel := context.WithTimeout(dialCtx, 5*time.Second)
		defer connCancel()
		conn, err := h.Connect(connCtx, dest, getTURNInfo(), true)
		if err != nil {
			if errors.Is(err, protocol.ErrQuotaReached) || errors.Is(err, protocol.ErrUnauthorized) {
				D.log.Warn("peer connection failed with TURN error, triggering full reconnect", "peer_idx", idx, "error", err)
				fullReconnect(err.Error())
			}
		}
		return conn, err
	}

	peerConn := connection.NewPeerConn(sessionCtx)
	peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

	for idx := 0; idx < numPeers; idx++ {
		_ = peerConn.AddPeer(dialFn)
	}

	D.stateMu.Lock()
	D.cancel = sessionCancel
	D.peerConn = peerConn
	D.stateMu.Unlock()
	success = true
	D.log.Info("direct session connected", "gateway", cfg.Gateway, "peers", numPeers)
	return nil
}
