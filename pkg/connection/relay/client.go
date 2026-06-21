package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/protocol"
)

// connectClientSession establishes the platform, underlay, and tinymux session for the client.
func (D *Handler) connectClientSession() error {
	D.reconnectMu.Lock()
	defer D.reconnectMu.Unlock()

	D.stateMu.Lock()
	oldCancel := D.cancel
	oldMuxClient := D.muxClient
	oldPeerConn := D.peerConn
	oldPlatform := D.platform
	cfg := D.clientConfig
	reconnectCtx := D.reconnectCtx
	D.cancel = nil
	D.muxClient = nil
	D.peerConn = nil
	D.platform = nil
	D.stateMu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldMuxClient != nil {
		_ = oldMuxClient.Disconnect()
		_ = oldMuxClient.Close()
	}
	if oldPeerConn != nil {
		_ = oldPeerConn.Close()
	}
	if oldPlatform != nil {
		_ = oldPlatform.Close()
	}

	if cfg == nil {
		return errors.New("relay reconnect requires client config")
	}
	if reconnectCtx == nil {
		return errors.New("relay reconnect context is not available")
	}

	platformHandler, err := platform.GetHandler(cfg.PlatformID)
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
		_ = platformHandler.Close()
		return err
	}*/

	if !protocol.HandlerExists(cfg.Proto) {
		_ = platformHandler.Disconnect()
		return fmt.Errorf("protocol handler %s not found", cfg.Proto)
	}

	turnInfo := platformHandler.GetTURNInfo()
	dest, err := common.ResolveUDPAddr(cfg.Gateway)
	if err != nil {
		_ = platformHandler.Disconnect()
		return fmt.Errorf("invalid relay gateway %q: %w", cfg.Gateway, err)
	}

	go relayWatchPlatform(sessionCtx, events, D.log)

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

			D.log.Info("starting full reconnect", "reason", reason, "delay", delay)
			select {
			case <-sessionCtx.Done():
				return
			case <-time.After(delay):
			}

			for {
				if err := D.connectClientSession(); err == nil {
					return
				} else {
					D.log.Warn("full reconnect failed, retrying", "delay", delay, "error", err)
				}

				D.stateMu.RLock()
				ctx := D.reconnectCtx
				D.stateMu.RUnlock()
				if ctx == nil {
					return
				}

				select {
				case <-ctx.Done():
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

		if turnConnCount >= platCfg.MaxTURNConnections && platCfg.MaxTURNConnections > 0 && len(turnInfo) > 1 {
			turnServerIdx++
			if turnServerIdx >= len(turnInfo) {
				turnServerIdx = 0
			}
			turnConnCount = 0
		}
		turnConnCount++
		return turnInfo[turnServerIdx]
	}

	type connPair struct {
		raw, enc net.Conn
		idx      int
	}

	connectAndEncrypt := func(ctx context.Context, idx int) (raw, enc net.Conn, err error) {
		h, _ := protocol.GetHandler(cfg.Proto)
		h.SetLogger(D.log.With("peer_idx", idx))

		connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
		defer connCancel()

		raw, err = h.Connect(connCtx, dest, getTURNInfo(), true)
		if err != nil {
			return
		}

		_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))

		enc, err = connection.WrapClientEncryptedConn(raw, cfg.PubKey)
		if err != nil {
			_ = raw.Close()
			raw = nil
			return
		}

		_ = raw.SetDeadline(time.Time{})

		return
	}

	pickConn := func(p connPair) net.Conn {
		if cfg.Encryption == "full" {
			return p.enc
		}
		return p.raw
	}

	var primaryMu sync.Mutex
	var rejected bool
	var primaryReady bool
	var assignedUUID [16]byte
	var uuidReady = make(chan struct{})

	dialFn := func(dialCtx context.Context, idx int) (net.Conn, error) {
		raw, enc, err := connectAndEncrypt(dialCtx, idx)
		if err != nil {
			if errors.Is(err, protocol.ErrQuotaReached) || errors.Is(err, protocol.ErrUnauthorized) {
				fullReconnect(err.Error())
			}
			return nil, err
		}

	primaryLoop:
		for {
			primaryMu.Lock()
			isPrimary := !primaryReady
			if isPrimary {
				primaryReady = true
			}
			currentReady := uuidReady
			primaryMu.Unlock()

			if rejected {
				return nil, connection.ErrPeerDone
			}

			if isPrimary {
				_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
				cfgJson, err := cfg.ToJSON(false, true)
				if err != nil {
					_ = raw.Close()
					primaryMu.Lock()
					primaryReady = false
					close(currentReady)
					uuidReady = make(chan struct{})
					primaryMu.Unlock()
					return nil, err
				}

				uuidBytes, hErr := doClientPrimaryHandshake(enc, cfgJson)
				_ = raw.SetDeadline(time.Time{})

				if hErr != nil {
					_ = raw.Close()
					var ackErr *ErrAckRejected
					if errors.As(hErr, &ackErr) {
						fullReconnect(hErr.Error())
						primaryMu.Lock()
						primaryReady = false
						rejected = true
						close(currentReady)
						uuidReady = make(chan struct{})
						primaryMu.Unlock()
						return nil, connection.ErrPeerDone
					}

					primaryMu.Lock()
					primaryReady = false
					close(currentReady)
					uuidReady = make(chan struct{})
					primaryMu.Unlock()
					return nil, hErr
				}

				primaryMu.Lock()
				assignedUUID = uuidBytes
				D.log.Info("relay session established", "peer_idx", idx, "session_uuid", uuid.UUID(assignedUUID).String())
				close(currentReady)
				primaryMu.Unlock()
				return pickConn(connPair{raw, enc, idx}), nil
			}

			select {
			case <-currentReady:
				primaryMu.Lock()
				ready := primaryReady
				primaryMu.Unlock()
				if ready {
					break primaryLoop
				}
			case <-dialCtx.Done():
				_ = raw.Close()
				return nil, dialCtx.Err()
			}

			if rejected {
				return nil, connection.ErrPeerDone
			}
		}

		primaryMu.Lock()
		localUUID := assignedUUID
		primaryMu.Unlock()

		_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
		sErr := doClientSecondaryHandshake(enc, localUUID, cfg.UserUUID)
		_ = raw.SetDeadline(time.Time{})

		if sErr != nil {
			_ = raw.Close()
			var ackErr *ErrAckRejected
			if errors.As(sErr, &ackErr) {
				fullReconnect(sErr.Error())
				return nil, connection.ErrPeerDone
			}
			return nil, sErr
		}

		return pickConn(connPair{raw, enc, idx}), nil
	}

	peerConn := connection.NewPeerConn(sessionCtx)
	peerConn.SetLogger(D.log)
	peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

	for idx := 0; idx < numPeers; idx++ {
		_ = peerConn.AddPeer(dialFn)
	}

	muxClient, err := connection.NewTinyMuxClient(sessionCtx, peerConn)
	if err != nil {
		_ = peerConn.Close()
		return fmt.Errorf("tinymux setup: %w", err)
	}

	platCfg = platformHandler.GetConfig()
	if platCfg.BandwidthRelay > 0 {
		muxClient.SetRateLimit(platCfg.BandwidthRelay * float64(numPeers))
	}

	go func() {
		select {
		case <-muxClient.Done():
			fullReconnect("tinymux session died")
		case <-sessionCtx.Done():
		}
	}()

	sessionUUIDStr := uuid.UUID(assignedUUID).String()
	D.stateMu.Lock()
	D.cancel = sessionCancel
	D.platform = platformHandler
	D.muxClient = muxClient
	D.peerConn = peerConn
	D.sessionUUID = sessionUUIDStr
	D.stateMu.Unlock()
	success = true

	D.log.Info("relay client session started", "peers", numPeers)
	return nil
}
