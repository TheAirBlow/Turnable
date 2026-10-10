package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// logBroadcast fans out log records to all connected service clients
type logBroadcast struct {
	mu   sync.RWMutex             // guards subs
	subs map[*clientConn]struct{} // subscribed clients
}

// subscribe registers a connection to receive all log records
func (b *logBroadcast) subscribe(c *clientConn) {
	b.mu.Lock()
	b.subs[c] = struct{}{}
	b.mu.Unlock()
}

// unsubscribe removes a connection from log delivery
func (b *logBroadcast) unsubscribe(c *clientConn) {
	b.mu.Lock()
	delete(b.subs, c)
	b.mu.Unlock()
}

// dispatch sends a log record to all subscribed connections without blocking
func (b *logBroadcast) dispatch(rec *pb.LogRecord) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for c := range b.subs {
		c.sendLog(rec)
	}
}

// LogRelayHandler is a slog handler that forwards records to all service clients and an inner handler
type LogRelayHandler struct {
	inner     slog.Handler  // handler records are also passed to
	broadcast *logBroadcast // subscribers to forward records to
	attrs     []slog.Attr   // attributes added with WithAttrs
	groups    []string      // groups added with WithGroup
}

// newLogRelayHandler wraps an existing handler with a log relay
func newLogRelayHandler(inner slog.Handler) *LogRelayHandler {
	return &LogRelayHandler{
		inner:     inner,
		broadcast: &logBroadcast{subs: make(map[*clientConn]struct{})},
	}
}

// Enabled delegates to the inner handler
func (h *LogRelayHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle forwards the record to the inner handler and broadcasts it to all service clients
func (h *LogRelayHandler) Handle(ctx context.Context, r slog.Record) error {
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}

	allAttrs := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	allAttrs = append(allAttrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		allAttrs = append(allAttrs, a)
		return true
	})

	h.broadcast.dispatch(&pb.LogRecord{
		Time:    r.Time.UnixNano(),
		Level:   int32(r.Level),
		Message: r.Message,
		Attrs:   flattenAttrs(allAttrs, h.groups),
	})
	return nil
}

// WithAttrs returns a cloned handler with additional attributes
func (h *LogRelayHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cloned := *h
	cloned.inner = h.inner.WithAttrs(attrs)
	cloned.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &cloned
}

// WithGroup returns a cloned handler with an additional group
func (h *LogRelayHandler) WithGroup(name string) slog.Handler {
	cloned := *h
	cloned.inner = h.inner.WithGroup(name)
	if strings.TrimSpace(name) != "" {
		cloned.groups = append(append([]string(nil), h.groups...), name)
	}
	return &cloned
}

// flattenAttrs recursively flattens slog attrs into pb.LogAttr pairs
func flattenAttrs(attrs []slog.Attr, groups []string) []*pb.LogAttr {
	var result []*pb.LogAttr
	for _, a := range attrs {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			continue
		}

		if a.Value.Kind() == slog.KindGroup {
			var ng []string
			if a.Key != "" {
				ng = append(append([]string(nil), groups...), a.Key)
			} else {
				ng = groups
			}
			result = append(result, flattenAttrs(a.Value.Group(), ng)...)
			continue
		}

		keyParts := append(append([]string(nil), groups...), a.Key)
		key := strings.Join(keyParts, ".")

		var val string
		switch a.Value.Kind() {
		case slog.KindString:
			val = a.Value.String()
		case slog.KindTime:
			val = a.Value.Time().Format(time.RFC3339Nano)
		default:
			val = fmt.Sprintf("%v", a.Value.Any())
		}

		result = append(result, &pb.LogAttr{Key: key, Value: val})
	}
	return result
}
