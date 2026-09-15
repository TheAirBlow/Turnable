package vk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/protocol"
)

const (
	vkAuthCacheLocalName  = ".vk_auth_cache"     // VK auth cache file name in the working directory
	vkAuthCacheGlobalName = "vk_auth_cache.json" // VK auth cache file name in the global config directory
)

// vkAuthEntry stores cached VK credentials for one call
type vkAuthEntry struct {
	Username            string              `json:"username"`
	MessagesAccessToken string              `json:"messages_access_token"`
	AnonymToken         string              `json:"anonym_token"`
	SessionKey          string              `json:"session_key"`
	TURNInfos           []protocol.TURNInfo `json:"turn_infos,omitempty"`
}

// vkAuthCacheFile is the JSON container for VK auth cache
type vkAuthCacheFile struct {
	Entries map[string]vkAuthEntry `json:"entries"`
}

// vkAuthCacheState tracks cached VK credentials and per-call authorization locks
var vkAuthCacheState = struct {
	mu      sync.Mutex
	entries map[string]vkAuthEntry
	locks   map[string]*sync.Mutex
	warn    sync.Once
}{
	entries: make(map[string]vkAuthEntry),
	locks:   make(map[string]*sync.Mutex),
}

// init loads VK auth cache state from disk
func init() {
	primary, fallback := common.CachePaths(vkAuthCacheLocalName, vkAuthCacheGlobalName)
	if loadVKAuthCacheFrom(primary) {
		return
	}

	loadVKAuthCacheFrom(fallback)
}

// loadVKAuthCacheFrom loads cache entries from a single cache file path
func loadVKAuthCacheFrom(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false
	}

	var payload vkAuthCacheFile
	if err := json.Unmarshal(data, &payload); err != nil || len(payload.Entries) == 0 {
		return false
	}

	vkAuthCacheState.mu.Lock()
	vkAuthCacheState.entries = payload.Entries
	vkAuthCacheState.mu.Unlock()
	return true
}

// persistVKAuthCache persists the current VK auth cache to disk; vkAuthCacheState.mu must be held
func persistVKAuthCache() {
	data, err := json.Marshal(vkAuthCacheFile{Entries: vkAuthCacheState.entries})
	if err != nil {
		vkAuthCacheState.warn.Do(func() {
			slog.Warn("failed to serialize vk auth cache", "error", err)
		})
		return
	}

	primary, fallback := common.CachePaths(vkAuthCacheLocalName, vkAuthCacheGlobalName)

	if writeVKAuthCache(primary, data) == nil {
		return
	}
	if writeVKAuthCache(fallback, data) == nil {
		return
	}

	vkAuthCacheState.warn.Do(func() {
		slog.Warn("failed to persist vk auth cache", "primary", primary, "fallback", fallback)
	})
}

// writeVKAuthCache writes VK auth cache JSON to the given file path, readable only by its owner
func writeVKAuthCache(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty cache path")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// vkAuthLock returns the mutex serializing authorization for one call
func vkAuthLock(key string) *sync.Mutex {
	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	lock, ok := vkAuthCacheState.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		vkAuthCacheState.locks[key] = lock
	}
	return lock
}

// getCachedVKAuth returns the cached VK credentials for a call
func getCachedVKAuth(key string) (vkAuthEntry, bool) {
	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	entry, ok := vkAuthCacheState.entries[key]
	return entry, ok
}

// putCachedVKAuth stores VK credentials for a call and persists cache to disk
func putCachedVKAuth(key string, entry vkAuthEntry) {
	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	vkAuthCacheState.entries[key] = entry
	persistVKAuthCache()
}

// InvalidateTURNInfo discards cached TURN credentials after the TURN server rejects them
func (V *Handler) InvalidateTURNInfo(info protocol.TURNInfo) {
	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	for key, entry := range vkAuthCacheState.entries {
		for _, cached := range entry.TURNInfos {
			if cached.Username != info.Username || cached.Password != info.Password {
				continue
			}

			entry.TURNInfos = nil
			vkAuthCacheState.entries[key] = entry
			persistVKAuthCache()
			slog.Info("vk cached turn credentials invalidated")
			return
		}
	}
}

// turnUsable reports whether the entry has TURN credentials that have not reached their expiration date
func (e vkAuthEntry) turnUsable() bool {
	if len(e.TURNInfos) == 0 {
		return false
	}

	for _, info := range e.TURNInfos {
		if expiry, ok := turnCredentialExpiry(info.Username); ok && !time.Now().Before(expiry) {
			return false
		}
	}
	return true
}

// turnCredentialExpiry parses the expiration date embedded in a "timestamp:user" TURN username
func turnCredentialExpiry(username string) (time.Time, bool) {
	raw, _, found := strings.Cut(username, ":")
	if !found {
		return time.Time{}, false
	}

	timestamp, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(timestamp, 0), true
}

// messagesTokenExpired reports whether an anonymous messages token is missing or has reached its JWT expiration date
func messagesTokenExpired(token string) bool {
	if token == "" {
		return true
	}

	parts := strings.Split(strings.TrimPrefix(token, "anonym."), ".")
	if len(parts) != 3 {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return false
	}
	return !time.Now().Before(time.Unix(claims.Exp, 0))
}
