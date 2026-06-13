package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/internal/connection"
	platformpkg "github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
)

// connectSession establishes all peer connections and initializes the PeerConn
func (D *Handler) connectSession() error {
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

	if err := platformHandler.Authorize(cfg.CallID, common.GenerateUsername()); err != nil {
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

	peerConn := connection.NewPeerConn(sessionCtx)
	peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

	for idx := 0; idx < numPeers; idx++ {
		go func() {
			delay := connection.PeerReconnectInit
			for {
				raw, err := dial(idx, sessionCtx)
				if err != nil {
					if sessionCtx.Err() != nil {
						return
					}
					if errors.Is(err, protocol.ErrQuotaReached) {
						D.log.Warn("peer quota reached, backing off", "peer_idx", idx, "delay", connection.PeerQuotaBackoff)
						delay = connection.PeerQuotaBackoff
					}

					D.log.Warn("peer connect failed", "peer_idx", idx, "error", err, "delay", delay)
					select {
					case <-sessionCtx.Done():
						return
					case <-time.After(delay):
					}

					delay = min(delay*2, connection.PeerReconnectMax)
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
