package common

import (
	"context"
	"encoding/json"
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

// warmupDomains contains a list of domains to resolve when warmup is requested
var warmupDomains = []string{
	"vk.com",
	"api.vk.com",
	"login.vk.com",
	"id.vk.com",
	"static.vk.com",
	"calls.okcdn.ru",
	"videowebrtc.okcdn.ru",
}

// dnsCacheEntry describes one cached DNS answer
type dnsCacheEntry struct {
	IPs []string `json:"ips"`
}

// dnsCacheFile is the JSON container for DNS cache
type dnsCacheFile struct {
	Entries map[string]dnsCacheEntry `json:"entries"`
}

// init loads DNS cache state from disk
func init() {
	primary, fallback := cachePaths()
	if loadDNSCacheFrom(primary) {
		return
	}

	loadDNSCacheFrom(fallback)
}

// cachePaths returns primary and fallback cache file paths
func cachePaths() (string, string) {
	fallback := ".dns_cache"
	if cwd, err := os.Getwd(); err == nil {
		fallback = filepath.Join(cwd, ".dns_cache")
	}

	configDir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(configDir) == "" {
		return "", fallback
	}

	primary := filepath.Join(configDir, "turnable", "dns_cache.json")
	return primary, fallback
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

	primary, fallback := cachePaths()

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

// cacheSet updates a cache entry and persists cache to disk
func cacheSet(host string, ips []net.IP) {
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
	dnsCache[host] = dnsCacheEntry{IPs: stringsIP}
	dnsCacheMu.Unlock()
	persistDNSCache()
}

// resolverLookup performs a native DNS lookup with timeout
func resolverLookup(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := globalResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	return ips, nil
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

// Lookup resolves a hostname from native resolver, falling back to cache only on failure.
func Lookup(host string) ([]net.IP, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	resolvedIPs, err := resolverLookup(host)
	if err == nil {
		cacheSet(host, resolvedIPs)
		return resolvedIPs, nil
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
	dialer := &net.Dialer{Timeout: 10 * time.Second}
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
