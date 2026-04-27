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

// TurnableClient represents a Turnable client
type TurnableClient struct {
	Config config.ClientConfig

	running atomic.Bool
	handler connection.Handler

	ctx    context.Context
	cancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (c *TurnableClient) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	c.log = log
}

// NewTurnableClient creates a new Turnable client from the specified ClientConfig
func NewTurnableClient(cfg config.ClientConfig) *TurnableClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &TurnableClient{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
		log:    slog.Default(),
	}
}

// Start starts the Turnable client using the provided local tunnel handler
func (c *TurnableClient) Start(listenAddr string) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			c.running.Store(false)
		}
	}()

	socket := SocketHandler{}
	socket.SetLogger(c.log)

	connHandler, err := connection.GetHandler(c.Config.Type)
	if err != nil {
		return fmt.Errorf("get connection handler: %w", err)
	}

	connHandler.SetLogger(c.log)

	if err := connHandler.Connect(c.Config); err != nil {
		_ = connHandler.Close()
		return fmt.Errorf("connect: %w", err)
	}

	c.handler = connHandler

	acceptCh, err := socket.Open(c.ctx, c.Config.Socket, listenAddr)
	if err != nil {
		_ = connHandler.Close()
		return fmt.Errorf("open tunnel: %w", err)
	}

	go c.acceptClients(acceptCh)

	success = true
	return nil
}

// IsRunning returns whether the Turnable client is currently running
func (c *TurnableClient) IsRunning() bool {
	return c.running.Load()
}

// Stop stops the Turnable client
func (c *TurnableClient) Stop() error {
	if !c.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	c.cancel()

	var err error
	if c.handler != nil {
		err = c.handler.Disconnect()
	}

	return err
}

// acceptClients accepts local clients and handles them
func (c *TurnableClient) acceptClients(acceptCh <-chan AcceptedClient) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case client, ok := <-acceptCh:
			if !ok {
				return
			}
			go c.handleClient(client)
		}
	}
}

// handleClient opens a tinymux channel and pipes the local client through it
func (c *TurnableClient) handleClient(local AcceptedClient) {
	if c.handler == nil {
		c.log.Warn("no active handler for local client")
		_ = local.Stream.Close()
		return
	}

	channel, err := c.handler.OpenChannel()
	if err != nil {
		if !errors.Is(err, connection.ErrReconnecting) {
			c.log.Warn("failed to open channel for local client", "error", err)
		}
		_ = local.Stream.Close()
		return
	}

	c.log.Debug("piping local client to channel")
	pipeStreams(local.Stream, channel)
}
