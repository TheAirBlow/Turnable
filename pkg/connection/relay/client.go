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

	if D.cancel != nil {
		D.cancel()
		D.cancel = nil
	}
	if D.muxClient != nil {
		_ = D.muxClient.Disconnect()
		_ = D.muxClient.Close()
		D.muxClient = nil
	}
	if D.peerConn != nil {
		_ = D.peerConn.Close()
		D.peerConn = nil
	}
	if D.platform != nil {
		_ = D.platform.Close()
		D.platform = nil
	}

	cfg := D.clientConfig
	if cfg == nil {
		return errors.New("relay reconnect requires client config")
	}

	platformHandler, err := platform.GetHandler(cfg.PlatformID)
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

	go relayWatchPlatform(sessionCtx, events, D.log)

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

				ctx := D.reconnectCtx
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

	type connPair struct {
		raw, enc net.Conn
		idx      int
	}

	connCh := make(chan connPair, numPeers)
	peerRetryMu := sync.Mutex{}
	peerRetryDelay := make(map[int]time.Duration)

	getDelay := func(prev time.Duration, err error) time.Duration {
		if errors.Is(err, protocol.ErrQuotaReached) {
			if prev < connection.PeerQuotaBackoff {
				return connection.PeerQuotaBackoff
			}
			return min(prev*2, peerHandshakeRetryMax)
		}

		if prev <= 0 {
			return connection.PeerReconnectInit
		}
		return min(prev*2, peerHandshakeRetryMax)
	}

	resetPeerRetryDelay := func(idx int) {
		peerRetryMu.Lock()
		delete(peerRetryDelay, idx)
		peerRetryMu.Unlock()
	}

	connectAndEncrypt := func(idx int, ctx context.Context) (raw, enc net.Conn, err error) {
		h, _ := protocol.GetHandler(cfg.Proto)
		h.SetLogger(D.log.With("peer_idx", idx))

		connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
		defer connCancel()

		raw, err = h.Connect(connCtx, dest, relayInfo, true)
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

	spawnPeer := func(idx int, initialDelay time.Duration) {
		go func() {
			delay := connection.PeerReconnectInit
			if initialDelay > 0 {
				select {
				case <-sessionCtx.Done():
					return
				case <-time.After(initialDelay):
				}
			}

			for {
				raw, enc, err := connectAndEncrypt(idx, sessionCtx)
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

				select {
				case connCh <- connPair{raw, enc, idx}:
					return
				case <-sessionCtx.Done():
					_ = raw.Close()
					return
				}
			}
		}()
	}

	schedulePeerRetry := func(idx int, err error) {
		peerRetryMu.Lock()
		next := getDelay(peerRetryDelay[idx], err)
		peerRetryDelay[idx] = next
		peerRetryMu.Unlock()

		D.log.Warn("scheduling peer retry", "peer_idx", idx, "delay", next, "error", err)
		spawnPeer(idx, next)
	}

	for i := 0; i < numPeers; i++ {
		spawnPeer(i, 0)
	}

	pickConn := func(p connPair) net.Conn {
		if cfg.Encryption == "full" {
			return p.enc
		}
		return p.raw
	}

	var assignedUUID [16]byte
	makePeerReconnectFn := func(idx int) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			raw, enc, err := connectAndEncrypt(idx, ctx)
			if err != nil {
				return nil, err
			}

			_ = raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			err = doClientSecondaryHandshake(enc, assignedUUID, cfg.UserUUID)
			_ = raw.SetDeadline(time.Time{})

			if err != nil {
				_ = raw.Close()
				var ackErr *ErrAckRejected
				if errors.As(err, &ackErr) {
					fullReconnect(err.Error())
					return nil, connection.ErrPeerDone
				}
				return nil, err
			}
			return pickConn(connPair{raw, enc, idx}), nil
		}
	}

	var peerConn *connection.PeerConn
	var muxClient *connection.TinyMuxClient
primaryLoop:
	for {
		select {
		case <-sessionCtx.Done():
			sessionCancel()
			_ = platformHandler.Disconnect()
			return sessionCtx.Err()
		case p := <-connCh:

			_ = p.raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
			cfgJson, err := cfg.ToJSON(false, true)
			if err != nil {
				_ = p.raw.Close()
				D.log.Warn("primary handshake failed", "peer_idx", p.idx, "error", err)
				schedulePeerRetry(p.idx, err)
				continue
			}

			uuidBytes, hErr := doClientPrimaryHandshake(p.enc, cfgJson)
			_ = p.raw.SetDeadline(time.Time{})
			if hErr != nil {
				_ = p.raw.Close()
				var ackErr *ErrAckRejected
				if errors.As(hErr, &ackErr) {
					sessionCancel()
					_ = platformHandler.Disconnect()
					return hErr
				}
				D.log.Warn("primary handshake failed", "peer_idx", p.idx, "error", hErr)
				schedulePeerRetry(p.idx, hErr)
				continue
			}

			assignedUUID = uuidBytes
			peerConn = connection.NewPeerConn(sessionCtx)
			peerConn.SetOnAllPeersGone(func() { fullReconnect("all peers disconnected") })

			if addErr := peerConn.AddPeer(pickConn(p), makePeerReconnectFn(p.idx)); addErr != nil {
				_ = p.raw.Close()
				_ = peerConn.Close()
				schedulePeerRetry(p.idx, addErr)
				continue
			}
			resetPeerRetryDelay(p.idx)

			var mErr error
			muxClient, mErr = connection.NewTinyMuxClient(sessionCtx, peerConn)
			if mErr != nil {
				_ = peerConn.Close()
				schedulePeerRetry(p.idx, mErr)
				continue
			}

			platCfg := platformHandler.GetConfig()
			if platCfg.BandwidthRelay > 0 {
				muxClient.SetRateLimit(platCfg.BandwidthRelay * float64(numPeers))
			}

			break primaryLoop
		}
	}

	go func() {
		select {
		case <-muxClient.Done():
			fullReconnect("tinymux session died")
		case <-sessionCtx.Done():
		}
	}()

	sessionUUIDStr := uuid.UUID(assignedUUID).String()
	sessionLog := D.log.With("session_uuid", sessionUUIDStr)
	muxClient.SetLogger(sessionLog)
	peerConn.SetLogger(sessionLog)
	D.cancel = sessionCancel
	D.platform = platformHandler
	D.muxClient = muxClient
	D.peerConn = peerConn
	D.sessionUUID = sessionUUIDStr

	D.log.Info("relay client session connected", "session_uuid", sessionUUIDStr, "peers", numPeers)

	go func() {
		defer func() {
			for {
				select {
				case p := <-connCh:
					_ = p.raw.Close()
				default:
					return
				}
			}
		}()
		for i := 0; i < numPeers-1; i++ {
			select {
			case <-sessionCtx.Done():
				return
			case p := <-connCh:
				go func(p connPair) {
					_ = p.raw.SetDeadline(time.Now().Add(relayHandshakeTimeout))
					sErr := doClientSecondaryHandshake(p.enc, assignedUUID, cfg.UserUUID)
					_ = p.raw.SetDeadline(time.Time{})

					if sErr != nil {
						_ = p.raw.Close()
						var ackErr *ErrAckRejected
						if errors.As(sErr, &ackErr) {
							fullReconnect(sErr.Error())
							return
						}
						D.log.Warn("secondary handshake failed", "peer_idx", p.idx, "error", sErr)
						schedulePeerRetry(p.idx, sErr)
						return
					}

					if addErr := peerConn.AddPeer(pickConn(p), makePeerReconnectFn(p.idx)); addErr != nil {
						D.log.Warn("peer add failed", "peer_idx", p.idx, "error", addErr)
						_ = p.raw.Close()
						schedulePeerRetry(p.idx, addErr)
						return
					}
					resetPeerRetryDelay(p.idx)
				}(p)
			}
		}
	}()

	return nil
}
