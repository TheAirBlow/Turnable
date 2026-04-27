package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/internal/connection"
)

// TurnableServer represents a Turnable server
type TurnableServer struct {
	Config config.ServerConfig

	running  atomic.Bool
	handlers []connection.Handler

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

// NewTurnableServer creates a new Turnable server from the provided ServerConfig
func NewTurnableServer(cfg config.ServerConfig) *TurnableServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &TurnableServer{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
		log:    slog.Default(),
	}
}

// Start starts all enabled connection handlers
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

	if err := s.Config.UpdateProvider(); err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	if s.Config.P2P.Enabled {
		return errors.New("P2P mode is not supported")
	}

	if s.Config.Relay.Enabled {
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

		go s.acceptClients(connHandler, socket)
	}

	success = true
	return nil
}

// IsRunning returns whether the Turnable server is currently running
func (s *TurnableServer) IsRunning() bool {
	return s.running.Load()
}

// Stop stops the Turnable server and all active handlers
func (s *TurnableServer) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	s.cancel()

	var err error
	for _, handler := range s.handlers {
		err = errors.Join(err, handler.Stop())
	}

	return errors.Join(err, s.Config.StopProvider())
}

// acceptClients accepts authenticated clients and handles them
func (s *TurnableServer) acceptClients(handler connection.Handler, socket SocketHandler) {
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

		go s.handleClient(client, socket)
	}
}

// handleClient dials the backend route and pipes the tinymux channel through it
func (s *TurnableServer) handleClient(client connection.ServerClient, socket SocketHandler) {
	routeCtx, routeCancel := context.WithCancel(s.ctx)
	defer routeCancel()

	routeIO, err := socket.Connect(routeCtx, client.Route)
	if err != nil {
		s.log.Warn("failed to connect to route", "addr", client.Address, "route", client.Route.ID, "error", err)
		_ = client.Conn.Close()
		return
	}

	s.log.Debug("piping client to route", "addr", client.Address, "route", client.Route.ID, "session", client.SessionUUID)
	pipeStreams(client.Conn, routeIO)
}
