package service

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync"
	"time"
)

const (
	throttleFailures = 5           // handshake failures from one host before it is blocked
	throttleWindow   = time.Minute // period failures are counted in
	throttleBlock    = time.Minute // how long a host stays blocked
	throttleMaxHosts = 4096        // tracked hosts before stale entries are swept
)

// failureRecord counts the failed handshakes of a host
type failureRecord struct {
	count int       // failures in the current window
	first time.Time // when the window started
	until time.Time // blocked until, zero when not blocked
}

// throttle blocks hosts that keep failing the handshake
type throttle struct {
	mu    sync.Mutex
	hosts map[string]*failureRecord
}

// newThrottle creates an empty throttle
func newThrottle() *throttle {
	return &throttle{hosts: make(map[string]*failureRecord)}
}

// hostOf returns the host of a remote address, empty for Unix sockets
func hostOf(addr net.Addr) string {
	if addr == nil || addr.Network() == "unix" {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

// blocked reports whether a host may not connect right now
func (t *throttle) blocked(host string) bool {
	if host == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	rec := t.hosts[host]
	return rec != nil && time.Now().Before(rec.until)
}

// fail records a failed handshake
func (t *throttle) fail(host string) {
	if host == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if len(t.hosts) >= throttleMaxHosts {
		for h, r := range t.hosts {
			if now.Sub(r.first) > throttleWindow && now.After(r.until) {
				delete(t.hosts, h)
			}
		}
	}

	rec := t.hosts[host]
	if rec == nil || now.Sub(rec.first) > throttleWindow {
		rec = &failureRecord{first: now}
		t.hosts[host] = rec
	}

	rec.count++
	if rec.count >= throttleFailures {
		rec.until = now.Add(throttleBlock)
		rec.count = 0
		rec.first = now
	}
}

// succeed forgets the failures of a host
func (t *throttle) succeed(host string) {
	if host == "" {
		return
	}

	t.mu.Lock()
	delete(t.hosts, host)
	t.mu.Unlock()
}

// keyFingerprint returns a short identifier of a public key for logs
func keyFingerprint(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}

	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
