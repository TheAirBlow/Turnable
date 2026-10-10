package common

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// pingURL is the URL used to test internet connectivity
const pingURL = "https://yandex.ru/"

// pingTimeout is the per-request timeout used while testing connectivity
const pingTimeout = 5 * time.Second

// pingRetryInterval is the pause between failed connectivity checks
const pingRetryInterval = 1 * time.Second

// pingOnce performs a single connectivity check request, ignoring the response body
func pingOnce(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

// connectivityWait is a single shared wait so concurrent callers don't each poll and log
type connectivityWait struct {
	done    chan struct{}      // closed once connectivity is back
	waiters int                // callers waiting on this probe
	cancel  context.CancelFunc // stops the probe when no one waits
}

var (
	connMu  sync.Mutex        // guards connCur
	connCur *connectivityWait // probe in progress, shared by concurrent waiters
)

// WaitForConnectivity blocks until an HTTP request to a known-reachable host succeeds or ctx is done
func WaitForConnectivity(ctx context.Context) (wasOffline bool, err error) {
	client := &http.Client{Timeout: pingTimeout}
	if pingOnce(ctx, client) {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	connMu.Lock()
	w := connCur
	if w == nil {
		pollCtx, cancel := context.WithCancel(context.Background())
		w = &connectivityWait{done: make(chan struct{}), cancel: cancel}
		connCur = w
		go pollConnectivity(pollCtx, w, client)
	}
	w.waiters++
	connMu.Unlock()

	select {
	case <-w.done:
		return true, nil
	case <-ctx.Done():
		connMu.Lock()
		w.waiters--
		if w.waiters == 0 && connCur == w {
			connCur = nil
			w.cancel()
		}
		connMu.Unlock()
		return false, ctx.Err()
	}
}

// pollConnectivity polls until the network is reachable, then releases every waiter
func pollConnectivity(ctx context.Context, w *connectivityWait, client *http.Client) {
	slog.Info("waiting for connectivity")
	start := time.Now()
	for !pingOnce(ctx, client) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(pingRetryInterval):
		}
	}

	connMu.Lock()
	if connCur == w {
		connCur = nil
	}
	connMu.Unlock()
	w.cancel()

	slog.Info(fmt.Sprintf("connectivity established after %s", time.Since(start).Round(time.Millisecond)))
	close(w.done)
}
