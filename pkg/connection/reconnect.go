package connection

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/platform"
)

// EventStream is a single-slot, latest-wins ConnectEvent channel with idempotent close
type EventStream struct {
	ch   chan ConnectEvent
	once sync.Once
}

// NewEventStream creates an empty EventStream
func NewEventStream() *EventStream {
	return &EventStream{ch: make(chan ConnectEvent, 1)}
}

// Chan returns the read-only event channel, closed once the stream is done for good
func (s *EventStream) Chan() <-chan ConnectEvent {
	return s.ch
}

// Publish delivers ev, replacing any unread pending event instead of blocking
func (s *EventStream) Publish(ev ConnectEvent) {
	select {
	case s.ch <- ev:
	default:
		select {
		case <-s.ch:
		default:
		}
		select {
		case s.ch <- ev:
		default:
		}
	}
}

// Close closes the stream; safe to call more than once or concurrently
func (s *EventStream) Close() {
	s.once.Do(func() { close(s.ch) })
}

// ReconnectBackoffInit is the initial wait between platform-error reconnect attempts
const ReconnectBackoffInit = 5 * time.Second

// ReconnectBackoffMax is the maximum wait between platform-error reconnect attempts
const ReconnectBackoffMax = 30 * time.Second

// reconnectImmediateWait is the fixed (non-growing) wait used for transient network errors
const reconnectImmediateWait = 1 * time.Second

// reconnectAction describes how a failed connection attempt should be retried
type reconnectAction int

const (
	reconnectBackoff   reconnectAction = iota // platform/application error: retry with exponential backoff
	reconnectImmediate                        // transient network error: wait for connectivity, retry at a fixed pace
	reconnectFatal                            // non-retryable error: stop trying
)

// classifyReconnectError decides the retry strategy for a failed connection attempt
func classifyReconnectError(err error) reconnectAction {
	if errors.Is(err, platform.ErrFatal) {
		return reconnectFatal
	}
	if isTransientNetworkError(err) {
		return reconnectImmediate
	}
	return reconnectBackoff
}

// isTransientNetworkError reports whether err looks like a transient connectivity failure
func isTransientNetworkError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EPIPE} {
		if errors.Is(err, errno) {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	for _, kw := range []string{"eof", "connection refused", "connection reset", "tls", "ssl", "certificate", "handshake", "timeout", "no route to host", "network is unreachable", "broken pipe"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}

	return false
}

// RunReconnectLoop calls connect repeatedly until it succeeds or ctx is cancelled, classifying
// each failure to retry immediately, back off, or give up for good. ctx must be the handler's
// stable, whole-lifetime context (not a per-session child), since connect itself may cancel
// whatever context the caller was previously using as soon as it is called.
func RunReconnectLoop(ctx context.Context, log *slog.Logger, reconnecting *atomic.Bool, events *EventStream, reason string, connect func() error) {
	if log == nil {
		log = slog.Default()
	}
	if !reconnecting.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer reconnecting.Store(false)
		log.Info("starting reconnect", "reason", reason)

		delay := ReconnectBackoffInit
		for {
			err := connect()
			if err == nil {
				events.Publish(ConnectEvent{Connected: true})
				return
			}

			action := classifyReconnectError(err)
			events.Publish(ConnectEvent{Connected: false, Err: err})

			if action == reconnectFatal {
				log.Error("reconnect stopped: fatal error", "error", err)
				events.Close()
				return
			}

			wait := delay
			if action == reconnectImmediate {
				wait = reconnectImmediateWait
				delay = ReconnectBackoffInit
				common.WaitForConnectivity()
			} else {
				delay = min(delay*2, ReconnectBackoffMax)
			}

			log.Warn("reconnect attempt failed, retrying", "immediate", action == reconnectImmediate, "wait", wait, "error", err)

			select {
			case <-ctx.Done():
				events.Close()
				return
			case <-time.After(wait):
			}
		}
	}()
}
