package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine/tunnels"
	"github.com/theairblow/turnable/pkg/internal/connection"
)

// VPNServer represents a VPN server.
type VPNServer struct {
	Config config.ServerConfig

	running  atomic.Bool
	handlers []connection.Handler

	ctx    context.Context
	cancel context.CancelFunc
}

// NewVPNServer creates a new VPN server from the provided ServerConfig.
func NewVPNServer(cfg config.ServerConfig) *VPNServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &VPNServer{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts all enabled server-side connection handlers.
func (s *VPNServer) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	if s.Config.P2P.Enabled {
		s.running.Store(false)
		return errors.New("P2P mode is not supported")
	}

	if s.Config.Relay.Enabled {
		slog.Info("starting vpn server relay handler")
		connHandler, err := connection.GetHandler("relay")
		if err != nil {
			slog.Error("failed to get relay handler", "error", err)
			return err
		}
		if err := connHandler.Start(s.Config); err != nil {
			slog.Error("failed to start relay handler", "error", err)
			s.running.Store(false)
			return err
		}
		s.handlers = append(s.handlers, connHandler)

		go s.acceptClients(connHandler)
	}

	return nil
}

// Stop stops the VPN server and all active handlers.
func (s *VPNServer) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return ErrNotRunning
	}
	slog.Info("stopping vpn server", "handlers", len(s.handlers))
	s.cancel()

	var err error
	for _, handler := range s.handlers {
		err = common.JoinErr(err, handler.Stop())
	}

	if err != nil {
		slog.Warn("vpn server stopped with errors", "error", err)
	} else {
		slog.Info("vpn server stopped")
	}
	return err
}

// acceptClients consumes authenticated connection-handler clients and forwards each one.
func (s *VPNServer) acceptClients(handler connection.Handler) {
	for client := range handler.AcceptNewClients(s.ctx) {
		if client.Route == nil || client.Config == nil || client.User == nil {
			slog.Warn("dropping client with incomplete metadata", "addr", client.Address)
			_ = client.IO.Close()
			continue
		}
		go s.handleClient(client)
	}
}

// handleClient dials the backend route and pipes the vpnmux channel through it.
func (s *VPNServer) handleClient(client connection.ServerClient) {
	tunnelHandler, err := tunnels.GetHandler("socket")
	if err != nil {
		slog.Warn("failed to get tunnel handler", "error", err)
		_ = client.IO.Close()
		return
	}

	routeCtx, routeCancel := context.WithCancel(s.ctx)
	defer routeCancel()

	routeIO, err := tunnelHandler.Connect(routeCtx, client.Route)
	if err != nil {
		slog.Warn("failed to connect to route", "addr", client.Address, "route", client.Route.ID, "error", err)
		_ = client.IO.Close()
		return
	}

	slog.Debug("piping client to route", "addr", client.Address, "route", client.Route.ID, "session", client.SessionUUID)
	pipeStreams(client.IO, routeIO)
}
