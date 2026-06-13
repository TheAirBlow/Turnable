package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/internal/connection"
	"github.com/theairblow/turnable/pkg/internal/platform"
	"github.com/theairblow/turnable/pkg/internal/protocol"
	"github.com/theairblow/turnable/pkg/internal/transport"
)

// handleIncomingPeer dispatches an incoming peer to the primary or secondary handler
func (D *Handler) handleIncomingPeer(
	ctx context.Context,
	client protocol.ServerClient,
	serverCfg *ServerConfig,
	out chan<- connection.ServerClient,
) error {
	_ = client.Conn.SetDeadline(time.Now().Add(relayHandshakeTimeout))

	encConn, err := connection.WrapServerEncryptedConn(client.Conn, serverCfg.PrivKey)
	if err != nil {
		_ = client.Conn.Close()
		return fmt.Errorf("peer encryption setup: %w", err)
	}

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := encConn.Write(challenge[:]); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write challenge: %w", err)
	}

	const maxHelloSize = 256 * 1024
	buf := make([]byte, maxHelloSize)
	n, err := encConn.Read(buf)
	if err != nil {
		_ = encConn.Close()
		return fmt.Errorf("read hello: %w", err)
	}
	if n < 9 {
		_ = encConn.Close()
		return errors.New("hello packet too short")
	}

	if [8]byte(buf[1:9]) != challenge {
		_ = encConn.Close()
		return errors.New("challenge mismatch: possible replay")
	}

	switch buf[0] {
	case relayHelloTypePrimary:
		return D.handlePrimaryPeer(ctx, client, encConn, buf[9:n], serverCfg, out)
	case relayHelloTypeSecondary:
		return D.handleSecondaryPeer(client, encConn, buf[9:n])
	default:
		_ = encConn.Close()
		return fmt.Errorf("unknown hello type %d", buf[0])
	}
}

// handlePrimaryPeer handles a primary peer connection
func (D *Handler) handlePrimaryPeer(
	ctx context.Context,
	client protocol.ServerClient,
	encConn *connection.EncryptedConn,
	helloPayload []byte,
	serverCfg *ServerConfig,
	out chan<- connection.ServerClient,
) error {
	configJSON, err := parsePrimaryHello(helloPayload)
	if err != nil {
		_ = writePrimaryAck(encConn, [16]byte{}, err.Error())
		_ = encConn.Close()
		return fmt.Errorf("parse primary hello: %w", err)
	}

	clientCfg, user, routes, err := D.validateClientConfig(configJSON)
	if err != nil {
		_ = writePrimaryAck(encConn, [16]byte{}, err.Error())
		_ = encConn.Close()
		return err
	}

	sessionUUID := uuid.New()
	var sessionUUIDBin [16]byte
	copy(sessionUUIDBin[:], sessionUUID[:])

	if err := writePrimaryAck(encConn, sessionUUIDBin, ""); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write primary ack: %w", err)
	}

	_ = encConn.SetDeadline(time.Time{})

	sessionUUIDStr := sessionUUID.String()
	sessionLog := D.log.With("session_uuid", sessionUUIDStr)
	D.log.Info("relay handshake started", "addr", client.Address)

	peerConn := connection.NewPeerConn(ctx)
	peerConn.SetLogger(sessionLog)
	newSess := &relayServerSession{
		peerConn: peerConn,
		userUUID: clientCfg.UserUUID,
		routes:   routes,
		fullEnc:  clientCfg.Encryption == "full",
	}

	actual, loaded := D.sessions.LoadOrStore(sessionUUIDStr, newSess)
	if loaded {
		existSess := actual.(*relayServerSession)
		var conn net.Conn
		if existSess.fullEnc {
			conn = encConn
		} else {
			conn = client.Conn
		}
		_ = existSess.peerConn.AddPeer(conn, nil)
		return nil
	}

	defer D.sessions.Delete(sessionUUIDStr)

	var peer0 net.Conn
	if clientCfg.Encryption == "full" {
		peer0 = encConn
	} else {
		peer0 = client.Conn
	}

	_ = peerConn.AddPeer(peer0, nil)

	muxServer, err := connection.NewTinyMuxServer(peerConn)
	if err != nil {
		_ = peerConn.Close()
		return fmt.Errorf("tinymux setup: %w", err)
	}

	defer func() { _ = muxServer.Close() }()
	newSess.muxServer.Store(muxServer)
	muxServer.SetLogger(sessionLog)

	platformHandler, err := platform.GetHandler(serverCfg.PlatformID)
	if err != nil {
		return err
	}

	platCfg := platformHandler.GetConfig()
	muxServer.SetRateLimit(platCfg.BandwidthRelay * float64(clientCfg.Peers))

	peerConn.SetOnAllPeersGone(func() { _ = muxServer.Close() })

	D.log.Info("relay handshake completed", "addr", client.Address, "session_uuid", sessionUUIDStr, "user_uuid", clientCfg.UserUUID, "routes", len(routes))

	for channel := range muxServer.AcceptChannels(ctx) {
		routeIdx := channel.RouteIdx
		if int(routeIdx) >= len(newSess.routes) {
			D.log.Warn("client sent invalid route index", "flow_id", channel.FlowID, "route_idx", routeIdx, "max", len(newSess.routes)-1)
			_ = channel.Conn.Close()
			continue
		}
		route := newSess.routes[routeIdx]

		transportHandler, wrapErr := transport.GetHandler(route.Transport)
		if wrapErr != nil {
			D.log.Warn("transport setup failed", "flow_id", channel.FlowID, "route", route.ID, "error", wrapErr)
			_ = channel.Conn.Close()
			continue
		}

		conn, wrapErr := transportHandler.WrapServer(channel.Conn)
		if wrapErr != nil {
			D.log.Warn("transport wrap failed", "flow_id", channel.FlowID, "error", wrapErr)
			_ = channel.Conn.Close()
			continue
		}

		select {
		case out <- connection.ServerClient{
			Address:     client.Address,
			Conn:        conn,
			User:        user,
			Routes:      newSess.routes,
			RouteIdx:    routeIdx,
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

// handleSecondaryPeer handles a secondary peer connection
func (D *Handler) handleSecondaryPeer(
	client protocol.ServerClient,
	encConn *connection.EncryptedConn,
	helloPayload []byte,
) error {
	sessionUUIDBin, userUUID, err := parseSecondaryHello(helloPayload)
	if err != nil {
		_ = encConn.Close()
		return fmt.Errorf("parse secondary hello: %w", err)
	}

	sessionUUIDStr := uuid.UUID(sessionUUIDBin).String()

	existing, loaded := D.sessions.Load(sessionUUIDStr)
	if !loaded {
		_ = writeSecondaryAck(encConn, "session not found")
		_ = encConn.Close()
		return fmt.Errorf("secondary peer: session %s not found", sessionUUIDStr)
	}

	sess := existing.(*relayServerSession)

	if sess.userUUID != userUUID {
		_ = writeSecondaryAck(encConn, "session not found")
		_ = encConn.Close()
		return fmt.Errorf("secondary peer: session mismatch for %s", sessionUUIDStr)
	}

	if err := writeSecondaryAck(encConn, ""); err != nil {
		_ = encConn.Close()
		return fmt.Errorf("write secondary ack: %w", err)
	}

	_ = encConn.SetDeadline(time.Time{})

	var conn net.Conn
	if sess.fullEnc {
		conn = encConn
	} else {
		conn = client.Conn
	}

	if err := sess.peerConn.AddPeer(conn, nil); err != nil {
		_ = encConn.Close()
		return err
	}

	return nil
}
