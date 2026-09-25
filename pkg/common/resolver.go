package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	globalResolver = &net.Resolver{}            // Native DNS resolver
	dnsCacheMu     sync.RWMutex                 // DNS cache mutex
	dnsCache       = map[string]dnsCacheEntry{} // DNS cache map
	cacheWarnOnce  sync.Once                    // cache warning sync
)

// defaultTTL is used for every entry since the native resolver does not expose real TTLs
const defaultTTL = 5 * time.Minute

const (
	dnsCacheLocalName  = ".dns_cache"     // DNS cache file name in the working directory
	dnsCacheGlobalName = "dns_cache.json" // DNS cache file name in the global config directory
)

// warmupDomains contains a list of domains to resolve when warmup is requested
var warmupDomains = []string{
	"vk.ru",
	"api.vk.ru",
	"login.vk.ru",
	"id.vk.ru",
	"static.vk.ru",
	"calls.okcdn.ru",
	"videowebrtc.okcdn.ru",
}

// dnsCacheEntry describes one cached DNS answer
type dnsCacheEntry struct {
	IPs    []string  `json:"ips"`
	TTL    int64     `json:"ttl_seconds"`
	Expiry time.Time `json:"expiry"`
}

// fresh reports whether the cache entry has not yet reached its expiration date
func (e dnsCacheEntry) fresh() bool {
	return !e.Expiry.IsZero() && time.Now().Before(e.Expiry)
}

// dnsCacheFile is the JSON container for DNS cache
type dnsCacheFile struct {
	Entries map[string]dnsCacheEntry `json:"entries"`
}

// init loads DNS cache state from disk
func init() {
	primary, fallback := CachePaths(dnsCacheLocalName, dnsCacheGlobalName)
	if loadDNSCacheFrom(primary) {
		return
	}

	loadDNSCacheFrom(fallback)
}

// loadDNSCacheFrom loads cache entries from a single cache file path
func loadDNSCacheFrom(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false
	}

	var payload dnsCacheFile
	if err := json.Unmarshal(data, &payload); err != nil || len(payload.Entries) == 0 {
		return false
	}

	dnsCacheMu.Lock()
	dnsCache = payload.Entries
	dnsCacheMu.Unlock()
	return true
}

// persistDNSCache persists the current DNS cache to disk
func persistDNSCache() {
	dnsCacheMu.RLock()
	entries := make(map[string]dnsCacheEntry, len(dnsCache))
	for host, entry := range dnsCache {
		entries[host] = entry
	}
	dnsCacheMu.RUnlock()
	payload := dnsCacheFile{Entries: entries}

	data, err := json.Marshal(payload)
	if err != nil {
		cacheWarnOnce.Do(func() {
			slog.Warn("failed to serialize dns cache", "error", err)
		})
		return
	}

	primary, fallback := CachePaths(dnsCacheLocalName, dnsCacheGlobalName)

	if tryWriteCache(primary, data) == nil {
		return
	}
	if tryWriteCache(fallback, data) == nil {
		return
	}

	cacheWarnOnce.Do(func() {
		slog.Warn("failed to persist dns cache", "primary", primary, "fallback", fallback)
	})
}

// tryWriteCache attempts to write DNS cache JSON to the given file path
func tryWriteCache(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty cache path")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o640)
}

// normalizeHost canonicalizes hostnames for cache keys
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// entryIPs parses cached string IPs into net.IP values
func entryIPs(entry dnsCacheEntry) []net.IP {
	ips := make([]net.IP, 0, len(entry.IPs))
	for _, s := range entry.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// cacheGet reads a cache entry by normalized host
func cacheGet(host string) (dnsCacheEntry, bool) {
	dnsCacheMu.RLock()
	entry, ok := dnsCache[host]
	dnsCacheMu.RUnlock()
	return entry, ok
}

// cacheSet updates a cache entry with its TTL-derived expiration and persists cache to disk
func cacheSet(host string, ips []net.IP, ttl time.Duration) {
	if len(ips) == 0 {
		return
	}

	stringsIP := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != nil {
			stringsIP = append(stringsIP, ip.String())
		}
	}

	dnsCacheMu.Lock()
	dnsCache[host] = dnsCacheEntry{
		IPs:    stringsIP,
		TTL:    int64(ttl.Seconds()),
		Expiry: time.Now().Add(ttl),
	}
	dnsCacheMu.Unlock()
	persistDNSCache()
}

// bumpCacheExpiry extends every cached entry's expiration by its own last recorded TTL
func bumpCacheExpiry() {
	dnsCacheMu.Lock()
	for host, entry := range dnsCache {
		if entry.TTL <= 0 {
			continue
		}
		entry.Expiry = entry.Expiry.Add(time.Duration(entry.TTL) * time.Second)
		dnsCache[host] = entry
	}
	dnsCacheMu.Unlock()
	persistDNSCache()
}

// isTimeout reports whether err represents a DNS request timeout
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// resolverLookup performs a native DNS lookup with timeout, returning addresses and their TTL
func resolverLookup(host string) ([]net.IP, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := globalResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, 0, err
	}

	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no addresses for %s", host)
	}

	return ips, defaultTTL, nil
}

// ResolveAll resolves and caches a predefined set of domains for warmup
func ResolveAll() error {
	for _, domain := range warmupDomains {
		host := normalizeHost(domain)
		_, err := Lookup(host)
		if err != nil {
			return err
		}
	}

	return nil
}

// Lookup resolves a hostname, preferring a fresh cache entry over a new DNS request
func Lookup(host string) ([]net.IP, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if entry, cached := cacheGet(host); cached && entry.fresh() {
		if cachedIPs := entryIPs(entry); len(cachedIPs) > 0 {
			return cachedIPs, nil
		}
	}

	resolvedIPs, ttl, err := resolverLookup(host)
	if err == nil {
		cacheSet(host, resolvedIPs, ttl)
		return resolvedIPs, nil
	}

	if isTimeout(err) {
		bumpCacheExpiry()
	}

	entry, cached := cacheGet(host)
	if cached {
		cachedIPs := entryIPs(entry)
		if len(cachedIPs) > 0 {
			return cachedIPs, nil
		}
	}

	return nil, fmt.Errorf("lookup %q: %w", host, err)
}

// ResolveUDPAddr resolves a UDP address using the cached DNS resolver
func ResolveUDPAddr(addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	ips, err := Lookup(host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

// ResolverDialContext returns a DialContext using the cached DNS resolver
func ResolverDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := Lookup(host)
		if err != nil {
			return nil, err
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}

		var conn net.Conn
		for _, ip := range ips {
			conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}

		return nil, err
	}
}
