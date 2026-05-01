package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
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

// Start starts the Turnable client
func (c *TurnableClient) Start(listenAddrs []string) error {
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

	baseAddr := "127.0.0.1:0"
	if len(listenAddrs) > 0 {
		baseAddr = listenAddrs[0]
	}

	baseHost, basePortStr, err := net.SplitHostPort(baseAddr)
	if err != nil {
		return fmt.Errorf("invalid base listen address %q: %w", baseAddr, err)
	}

	basePort, err := strconv.Atoi(basePortStr)
	if err != nil {
		return fmt.Errorf("invalid port in base listen address %q: %w", baseAddr, err)
	}

	for i, route := range c.Config.Routes {
		var addr string
		if i < len(listenAddrs) {
			addr = listenAddrs[i]
		} else {
			addr = net.JoinHostPort(baseHost, strconv.Itoa(basePort+i))
		}

		acceptCh, err := socket.Open(c.ctx, route.Socket, addr)
		if err != nil {
			_ = connHandler.Close()
			return fmt.Errorf("open tunnel for route %d (%s): %w", i, route.RouteID, err)
		}

		go c.acceptRouteClients(acceptCh, byte(i))
	}

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

// acceptRouteClients accepts local clients for a specific route and handles them
func (c *TurnableClient) acceptRouteClients(acceptCh <-chan AcceptedClient, routeIdx byte) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case client, ok := <-acceptCh:
			if !ok {
				return
			}
			go c.handleClient(client, routeIdx)
		}
	}
}

// handleClient opens a tinymux channel for the given route and pipes the local client through it
func (c *TurnableClient) handleClient(local AcceptedClient, routeIdx byte) {
	if c.handler == nil {
		c.log.Warn("no active handler for local client")
		_ = local.Stream.Close()
		return
	}

	channel, err := c.handler.OpenChannel(routeIdx)
	if err != nil {
		if !errors.Is(err, connection.ErrReconnecting) {
			c.log.Warn("failed to open channel for local client", "error", err)
		}
		_ = local.Stream.Close()
		return
	}

	c.log.Debug("piping local client to channel", "route_idx", routeIdx)
	pipeStreams(local.Stream, channel)
}
