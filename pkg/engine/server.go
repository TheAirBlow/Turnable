package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/internal/connection"
	"github.com/theairblow/turnable/pkg/tunnels"
)

// VPNServer represents a VPN server
type VPNServer struct {
	Config config.ServerConfig

	running  atomic.Bool
	handlers []connection.Handler

	ctx    context.Context
	cancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (s *VPNServer) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	s.log = log
}

// NewVPNServer creates a new VPN server from the provided ServerConfig
func NewVPNServer(cfg config.ServerConfig) *VPNServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &VPNServer{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
		log:    slog.Default(),
	}
}

// Start starts all enabled connection handlers
func (s *VPNServer) Start(tunnelHandler tunnels.Handler) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			s.running.Store(false)
		}
	}()

	if tunnelHandler == nil {
		return fmt.Errorf("tunnel handler is required")
	}

	tunnelHandler.SetLogger(s.log)

	if s.Config.P2P.Enabled {
		return errors.New("P2P mode is not supported")
	}

	if s.Config.Relay.Enabled {
		s.log.Info("starting vpn server relay handler")

		connHandler, err := connection.GetHandler("relay")
		if err != nil {
			s.log.Error("failed to get relay handler", "error", err)
			return err
		}

		connHandler.SetLogger(s.log)

		if err := connHandler.Start(s.Config); err != nil {
			s.log.Error("failed to start relay handler", "error", err)
			return err
		}

		s.handlers = append(s.handlers, connHandler)

		go s.acceptClients(connHandler, tunnelHandler)
	}

	success = true
	return nil
}

// Stop stops the VPN server and all active handlers
func (s *VPNServer) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	s.log.Info("stopping vpn server", "handlers", len(s.handlers))
	s.cancel()

	var err error
	for _, handler := range s.handlers {
		err = errors.Join(err, handler.Stop())
	}

	if err != nil {
		s.log.Warn("vpn server stopped with errors", "error", err)
	} else {
		s.log.Info("vpn server stopped")
	}

	return err
}

// acceptClients accepts authenticated clients and handles them
func (s *VPNServer) acceptClients(handler connection.Handler, tunnelHandler tunnels.Handler) {
	clientCh, err := handler.AcceptClients(s.ctx)
	if err != nil {
		s.log.Warn("accept clients failed", "error", err)
		return
	}

	for client := range clientCh {
		if client.Route == nil || client.Config == nil || client.User == nil {
			s.log.Warn("dropping client with incomplete metadata", "addr", client.Address)
			_ = client.Conn.Close()
			continue
		}

		go s.handleClient(client, tunnelHandler)
	}
}

// handleClient dials the backend route and pipes the tinymux channel through it
func (s *VPNServer) handleClient(client connection.ServerClient, tunnelHandler tunnels.Handler) {
	routeCtx, routeCancel := context.WithCancel(s.ctx)
	defer routeCancel()

	routeIO, err := tunnelHandler.Connect(routeCtx, client.Route)
	if err != nil {
		s.log.Warn("failed to connect to route", "addr", client.Address, "route", client.Route.ID, "error", err)
		_ = client.Conn.Close()
		return
	}

	s.log.Debug("piping client to route", "addr", client.Address, "route", client.Route.ID, "session", client.SessionUUID)
	pipeStreams(client.Conn, routeIO)
}
