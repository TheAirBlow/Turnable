package common

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.RWMutex         // Logging handler change mutex
	level = new(slog.LevelVar) // Current log level
)

// init initializes slog and defaults to using a pretty-print logging handler
func init() {
	level.Set(slog.LevelInfo)
	defaultHandler := NewPrettyHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	SetHandler(defaultHandler)
}

// ANSI color string
const (
	colorReset  = "\x1b[0m"
	colorDim    = "\x1b[2m"
	colorGray   = "\x1b[90m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
)

// PrettyHandler represents a pretty-print logging handler
type PrettyHandler struct {
	w      io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
	mu     *sync.Mutex
}

// NewPrettyHandler creates a new pretty-print logging handler for provided output stream with specified options
func NewPrettyHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	var leveler slog.Leveler = slog.LevelInfo
	if opts != nil && opts.Level != nil {
		leveler = opts.Level
	}
	return &PrettyHandler{
		w:     w,
		level: leveler,
		mu:    &sync.Mutex{},
	}
}

// Enabled checks whether the specified log level is enabled
func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// Handle performs pretty-print logging of the provided slog record
func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	if !h.Enabled(context.Background(), r.Level) {
		return nil
	}

	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	levelText, levelColor := levelStyle(r.Level)
	var b strings.Builder
	b.WriteString(colorGray)
	b.WriteString(ts.Format("2006-01-02 15:04:05.000"))
	b.WriteString(colorReset)
	b.WriteByte(' ')
	b.WriteString(levelColor)
	b.WriteByte('[')
	b.WriteString(levelText)
	b.WriteByte(']')
	b.WriteString(colorReset)
	b.WriteByte(' ')
	b.WriteString(r.Message)

	attrs := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	for _, a := range attrs {
		h.appendAttr(&b, h.groups, a)
	}
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

// WithAttrs adds additional attributes to all records logged via this handler
func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cloned := *h
	cloned.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cloned
}

// WithGroup adds additional groups to all records logged via this handler
func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	cloned := *h
	if strings.TrimSpace(name) != "" {
		cloned.groups = append(append([]string{}, h.groups...), name)
	}
	return &cloned
}

// appendAttr pretty-prints an attribute in to the given string builder
func (h *PrettyHandler) appendAttr(b *strings.Builder, groups []string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return
	}

	if attr.Value.Kind() == slog.KindGroup {
		nextGroups := groups
		if attr.Key != "" {
			nextGroups = append(append([]string{}, groups...), attr.Key)
		}
		for _, nested := range attr.Value.Group() {
			h.appendAttr(b, nextGroups, nested)
		}
		return
	}

	keyParts := append(append([]string{}, groups...), attr.Key)
	key := strings.Join(keyParts, ".")
	if key == "" {
		return
	}

	b.WriteByte(' ')
	b.WriteString(colorDim)
	b.WriteString(key)
	b.WriteString(colorReset)
	b.WriteByte('=')
	b.WriteString(formatValue(attr.Value))
}

// formatValue pretty-prints the given slog value
func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " \t\n\r") {
			return strconv.Quote(s)
		}
		return s
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", v.Any())
	}
}

// levelStyle provides the pretty-print style the given slog level
func levelStyle(level slog.Level) (string, string) {
	switch {
	case level <= slog.LevelDebug:
		return "DEBUG", colorCyan
	case level < slog.LevelWarn:
		return "INFO", colorGreen
	case level < slog.LevelError:
		return "WARN", colorYellow
	default:
		return "ERROR", colorRed
	}
}

// SetHandler sets the current slog handler
func SetHandler(h slog.Handler) {
	mu.Lock()
	defer mu.Unlock()
	slog.SetDefault(slog.New(h))
}

// SetLogLevel changes the current log level.
func SetLogLevel(newLevel int) {
	level.Set(slog.Level(newLevel))
}
