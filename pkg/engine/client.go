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

// VPNClient represents a VPN client
type VPNClient struct {
	Config config.ClientConfig

	running atomic.Bool
	handler connection.Handler

	ctx    context.Context
	cancel context.CancelFunc

	log *slog.Logger
}

// SetLogger changes the slog logger instance
func (c *VPNClient) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	c.log = log
}

// NewVPNClient creates a new VPN client from the specified ClientConfig
func NewVPNClient(cfg config.ClientConfig) *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &VPNClient{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
		log:    slog.Default(),
	}
}

// Start starts the VPN client using the provided local tunnel handler
func (c *VPNClient) Start(tunnelHandler tunnels.Handler) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			c.running.Store(false)
		}
	}()

	if tunnelHandler == nil {
		return fmt.Errorf("tunnel handler is required")
	}

	tunnelHandler.SetLogger(c.log)

	c.log.Info("starting vpn client", "connection_type", c.Config.Type)

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

	acceptCh, err := tunnelHandler.Open(c.ctx, c.Config.Socket)
	if err != nil {
		_ = connHandler.Close()
		return fmt.Errorf("open tunnel: %w", err)
	}

	go c.acceptClients(acceptCh)

	c.log.Info("vpn client started", "connection_type", c.Config.Type)
	success = true
	return nil
}

// Stop stops the VPN client
func (c *VPNClient) Stop() error {
	if !c.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	c.log.Info("stopping vpn client")
	c.cancel()

	var err error
	if c.handler != nil {
		err = c.handler.Disconnect()
	}

	if err != nil {
		c.log.Warn("vpn client stopped with errors", "error", err)
	} else {
		c.log.Info("vpn client stopped")
	}

	return err
}

// acceptClients accepts local clients and handles them
func (c *VPNClient) acceptClients(acceptCh <-chan tunnels.AcceptedClient) {
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
func (c *VPNClient) handleClient(local tunnels.AcceptedClient) {
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
