package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
)

// TurnableServer represents a Turnable server
type TurnableServer struct {
	Config   config.Config
	Provider providers.Provider

	running atomic.Bool
	handler connection.Handler

	ctx    context.Context
	cancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (s *TurnableServer) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	s.log = log
}

// NewTurnableServer creates a new Turnable server from the specified Config and Provider
func NewTurnableServer(cfg config.Config, provider providers.Provider) *TurnableServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &TurnableServer{
		Config:   cfg,
		Provider: provider,
		ctx:      ctx,
		cancel:   cancel,
		log:      slog.Default(),
	}
}

// Start starts the Turnable server
func (s *TurnableServer) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			s.running.Store(false)
		}
	}()

	socket := SocketHandler{}
	socket.SetLogger(s.log)

	if err := s.Config.Validate(); err != nil {
		return fmt.Errorf("failed to validate server config: %w", err)
	}

	innerCfg := s.Config.GetInner().(config.ServerConfig)

	connHandler, err := connection.GetHandler(innerCfg.Type)
	if err != nil {
		return fmt.Errorf("get connection handler: %w", err)
	}

	connHandler.SetLogger(s.log)

	if err := connHandler.Start(s.Config, s.Provider); err != nil {
		_ = connHandler.Stop()
		return fmt.Errorf("start handler: %w", err)
	}

	s.handler = connHandler

	success = true
	return nil
}

// IsRunning returns whether the Turnable server is currently running
func (s *TurnableServer) IsRunning() bool {
	return s.running.Load()
}

// Stop stops the Turnable server
func (s *TurnableServer) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	s.cancel()

	var err error
	if s.handler != nil {
		err = s.handler.Stop()
	}

	if s.Provider != nil {
		err = errors.Join(err, s.Provider.Stop())
	}

	return err
}

// acceptClients accepts authenticated clients and handles them
func (s *TurnableServer) acceptClients(handler connection.Handler, socket SocketHandler) {
	clientCh, err := handler.AcceptClients(s.ctx)
	if err != nil {
		s.log.Warn("accept clients failed", "error", err)
		return
	}

	for client := range clientCh {
		if len(client.Routes) == 0 || client.User == nil {
			s.log.Warn("dropping client with incomplete metadata", "addr", client.Address)
			_ = client.Conn.Close()
			continue
		}

		go s.handleClient(client, socket)
	}
}

// handleClient dials the backend route and pipes the tinymux channel through it
func (s *TurnableServer) handleClient(client connection.ServerClient, socket SocketHandler) {
	if int(client.RouteIdx) >= len(client.Routes) {
		s.log.Warn("invalid route index", "addr", client.Address, "route_idx", client.RouteIdx, "routes", len(client.Routes))
		_ = client.Conn.Close()
		return
	}

	route := &client.Routes[client.RouteIdx]
	routeCtx, routeCancel := context.WithCancel(s.ctx)
	defer routeCancel()

	routeIO, err := socket.Connect(routeCtx, route)
	if err != nil {
		s.log.Warn("failed to connect to route", "addr", client.Address, "route", route.ID, "error", err)
		_ = client.Conn.Close()
		return
	}

	s.log.Debug("piping client to route", "addr", client.Address, "route", route.ID, "session", client.SessionUUID)
	pipeStreams(client.Conn, routeIO)
}
