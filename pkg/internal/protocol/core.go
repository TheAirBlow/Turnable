package protocol

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	pionlog "github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// openDirectUnderlay opens an unconnected UDP socket
func openDirectUnderlay(dest net.Addr, proto string, log *slog.Logger) (net.PacketConn, net.Addr, error) {
	udpAddr, ok := dest.(*net.UDPAddr)
	if !ok {
		resolved, err := net.ResolveUDPAddr("udp", dest.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve udp destination: %w", err)
		}
		udpAddr = resolved
	}

	network := "udp4"
	if udpAddr.IP != nil && udpAddr.IP.To4() == nil {
		network = "udp6"
	}

	underlay, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open direct udp underlay: %w", err)
	}
	log.Debug("direct underlay opened", "proto", proto, "local", underlay.LocalAddr().String(), "remote", udpAddr.String())
	return underlay, udpAddr, nil
}

// openTURNUnderlay allocates a TURN relay socket
func openTURNUnderlay(relay RelayInfo, dest net.Addr, proto string, log *slog.Logger) (net.PacketConn, net.Addr, error) {
	if relay.Address == "" {
		return nil, nil, fmt.Errorf("%s turn requires turn address", proto)
	}
	if relay.Username == "" {
		return nil, nil, fmt.Errorf("%s turn requires turn username", proto)
	}
	if relay.Password == "" {
		return nil, nil, fmt.Errorf("%s turn requires turn password", proto)
	}

	network := "udp4"
	if udpAddr, ok := dest.(*net.UDPAddr); ok && udpAddr.IP != nil && udpAddr.IP.To4() == nil {
		network = "udp6"
	}

	underlay, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open local udp socket for turn: %w", err)
	}
	log.Debug("turn base socket opened", "proto", proto, "network", network, "local", underlay.LocalAddr().String(), "turn_server", relay.Address)

	infoLevel := slog.LevelInfo
	var connRef atomic.Pointer[turnPacketConn]
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: relay.Address,
		TURNServerAddr: relay.Address,
		Username:       relay.Username,
		Password:       relay.Password,
		Conn:           underlay,
		LoggerFactory: &turnLoggerFactory{log: log, level: &infoLevel, onFail: func() {
			// killing myself :3
			if c := connRef.Load(); c != nil {
				_ = c.Close()
			}
		}},
	})
	if err != nil {
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to create turn client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to start turn client listener: %w", err)
	}

	log.Debug("turn client listener started", "proto", proto, "turn_server", relay.Address)
	allocation, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to allocate turn relay: %w", err)
	}

	log.Debug("turn allocation created", "proto", proto, "turn_server", relay.Address)
	if err := client.CreatePermission(dest); err != nil {
		_ = allocation.Close()
		client.Close()
		_ = underlay.Close()
		return nil, nil, fmt.Errorf("failed to create turn permission for %s: %w", dest.String(), err)
	}

	log.Debug("turn permission created", "proto", proto, "peer", dest.String(), "turn_server", relay.Address)
	conn := &turnPacketConn{PacketConn: allocation, underlay: underlay, client: client}
	connRef.Store(conn)
	return conn, dest, nil
}

// connectViaTURN tries each TURN server in relay.Addresses and returns the first successful underlay
func connectViaTURN(relay RelayInfo, dest net.Addr, proto string, log *slog.Logger) (net.PacketConn, net.Addr, error) {
	servers := relay.Addresses
	if len(servers) == 0 {
		return nil, nil, fmt.Errorf("%s turn fallback requires turn address", proto)
	}
	log.Debug("trying turn servers", "proto", proto, "count", len(servers), "servers", strings.Join(servers, ","))

	var lastErr error
	for i, address := range servers {
		candidate := relay
		candidate.Address = address
		log.Debug("trying turn candidate", "proto", proto, "index", i+1, "count", len(servers), "server", address, "dest", dest.String())

		underlay, remoteAddr, err := openTURNUnderlay(candidate, dest, proto, log)
		if err != nil {
			lastErr = err
			log.Warn("turn candidate failed", "proto", proto, "index", i+1, "count", len(servers), "server", address, "error", err)
			continue
		}

		log.Debug("turn candidate selected", "proto", proto, "index", i+1, "count", len(servers), "server", address)
		return underlay, remoteAddr, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to establish %s over turn", proto)
	}
	if strings.Contains(lastErr.Error(), "Allocation Quota Reached") {
		return nil, nil, fmt.Errorf("%w: %w", ErrQuotaReached, lastErr)
	}

	return nil, nil, lastErr
}

// turnPacketConn wraps a TURN allocation and closes the TURN client and raw underlay on Close
type turnPacketConn struct {
	net.PacketConn
	underlay  net.PacketConn
	client    *turn.Client
	closeOnce sync.Once
}

// Close closes the TURN allocation, client, and raw underlay
func (c *turnPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.PacketConn.Close()
		if c.client != nil {
			c.client.Close()
		}
		if c.underlay != nil {
			err = errors.Join(err, c.underlay.Close())
		}
	})
	return err
}

// turnLoggerFactory represents a factory of scoped TURN loggers that forwards to slog
type turnLoggerFactory struct {
	log    *slog.Logger
	level  *slog.Level
	onFail func()
}

// NewLogger creates a new scoped TURN logger
func (f *turnLoggerFactory) NewLogger(scope string) pionlog.LeveledLogger {
	return &turnScopedLogger{log: f.log.With("scope", scope), level: f.level, onFail: f.onFail}
}

// turnScopedLogger represents a scoped TURN logger that forwards to slog
type turnScopedLogger struct {
	log    *slog.Logger
	level  *slog.Level
	onFail func()
}

// emit logs msg at lvl, dropping it if below the configured minimum level
func (l *turnScopedLogger) emit(lvl slog.Level, msg string) {
	if l.level != nil && lvl < *l.level {
		return
	}
	l.log.Log(nil, lvl, msg)
}

// Trace logs at trace level
func (l *turnScopedLogger) Trace(msg string) { l.emit(slog.LevelDebug-4, msg) }

// Debug logs at debug level
func (l *turnScopedLogger) Debug(msg string) { l.emit(slog.LevelDebug, msg) }

// Info logs at info level
func (l *turnScopedLogger) Info(msg string) { l.emit(slog.LevelInfo, msg) }

// Warn logs at warn level
func (l *turnScopedLogger) Warn(msg string) { l.emit(slog.LevelWarn, msg) }

// Error logs at error level
func (l *turnScopedLogger) Error(msg string) { l.emit(slog.LevelError, msg) }

// Tracef logs a formatted message at trace level
func (l *turnScopedLogger) Tracef(f string, a ...interface{}) {
	l.emit(slog.LevelDebug-4, fmt.Sprintf(f, a...))
}

// Debugf logs a formatted message at debug level
func (l *turnScopedLogger) Debugf(f string, a ...interface{}) {
	l.emit(slog.LevelDebug, fmt.Sprintf(f, a...))
}

// Infof logs a formatted message at info level
func (l *turnScopedLogger) Infof(f string, a ...interface{}) {
	l.emit(slog.LevelInfo, fmt.Sprintf(f, a...))
}

// Warnf logs a formatted message at warn level
func (l *turnScopedLogger) Warnf(f string, a ...interface{}) {
	l.emit(slog.LevelWarn, fmt.Sprintf(f, a...))
	if l.onFail != nil && strings.HasPrefix(f, "Failed to refresh") {
		l.onFail()
	}
}

// Errorf logs a formatted message at error level
func (l *turnScopedLogger) Errorf(f string, a ...interface{}) {
	l.emit(slog.LevelError, fmt.Sprintf(f, a...))
	if l.onFail != nil && strings.HasPrefix(f, "Fail to refresh") {
		l.onFail()
	}
}
