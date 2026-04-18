package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine/tunnels"
	"github.com/theairblow/turnable/pkg/internal/connection"
)

// VPNClient represents a VPN client
type VPNClient struct {
	Config config.ClientConfig

	running atomic.Bool
	handler connection.Handler

	ctx    context.Context
	cancel context.CancelFunc
}

// NewVPNClient creates a new VPN client from the specified ClientConfig
func NewVPNClient(cfg config.ClientConfig) *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &VPNClient{
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
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
		c.running.Store(false)
		return fmt.Errorf("tunnel handler is required")
	}

	slog.Info("starting vpn client", "connection_type", c.Config.Type)

	connHandler, err := connection.GetHandler(c.Config.Type)
	if err != nil {
		c.running.Store(false)
		return fmt.Errorf("get connection handler: %w", err)
	}

	if err := connHandler.Connect(c.Config); err != nil {
		_ = connHandler.Close()
		c.running.Store(false)
		return fmt.Errorf("connect: %w", err)
	}

	c.handler = connHandler

	acceptCh, err := tunnelHandler.Open(c.ctx, c.Config.Socket)
	if err != nil {
		_ = connHandler.Close()
		c.running.Store(false)
		return fmt.Errorf("open tunnel: %w", err)
	}

	go c.acceptClients(c.Config.Socket, acceptCh)

	slog.Info("vpn client started", "connection_type", c.Config.Type)
	success = true
	return nil
}

// Stop stops the VPN client
func (c *VPNClient) Stop() error {
	if !c.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	slog.Info("stopping vpn client")
	c.cancel()

	var err error
	if c.handler != nil {
		err = c.handler.Disconnect()
	}

	if err != nil {
		slog.Warn("vpn client stopped with errors", "error", err)
	} else {
		slog.Info("vpn client stopped")
	}

	return err
}

// acceptClients accepts local clients and handles them
func (c *VPNClient) acceptClients(socketType string, acceptCh <-chan tunnels.AcceptedClient) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case client, ok := <-acceptCh:
			if !ok {
				return
			}
			go c.handleClient(socketType, client)
		}
	}
}

// handleClient opens a tinymux channel and pipes the local client through it
func (c *VPNClient) handleClient(socketType string, local tunnels.AcceptedClient) {
	if c.handler == nil {
		slog.Warn("no active handler for local client")
		_ = local.Stream.Close()
		return
	}

	channel, err := c.handler.OpenChannel(socketType)
	if err != nil {
		if !errors.Is(err, connection.ErrReconnecting) {
			slog.Warn("failed to open channel for local client", "error", err)
		}
		_ = local.Stream.Close()
		return
	}

	slog.Debug("piping local client to channel", "socket", socketType)
	pipeStreams(local.Stream, channel)
}
