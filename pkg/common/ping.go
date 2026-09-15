package common

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// pingURL is the URL used to test internet connectivity
const pingURL = "https://yandex.ru/"

// pingTimeout is the per-request timeout used while testing connectivity
const pingTimeout = 5 * time.Second

// pingOnce performs a single connectivity check request, ignoring the response body
func pingOnce(client *http.Client) bool {
	resp, err := client.Get(pingURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

// WaitForConnectivity blocks until an HTTP request to a known-reachable host succeeds
func WaitForConnectivity() {
	client := &http.Client{Timeout: pingTimeout}

	start := time.Now()
	if pingOnce(client) {
		return
	}

	slog.Info("waiting for connectivity")
	for !pingOnce(client) {
	}

	slog.Info(fmt.Sprintf("connectivity established after %s", time.Since(start).Round(time.Millisecond)))
}
