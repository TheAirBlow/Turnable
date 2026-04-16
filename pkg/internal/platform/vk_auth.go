package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
)

// vkAPIError stores VK API error metadata, including captcha details
type vkAPIError struct {
	Code           int
	Message        string
	CaptchaSID     string
	CaptchaTS      string
	CaptchaAttempt string
	SessionToken   string
	AdFP           string
	RedirectURI    string
}

// vkCallsSessionData stores the anonymous VK calls login payload
type vkCallsSessionData struct {
	Version       int    `json:"version"`
	DeviceID      string `json:"device_id,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	ClientType    string `json:"client_type,omitempty"`
}

// vkStartedConversationInfo stores the conversation bootstrap payload returned by VK
type vkStartedConversationInfo struct {
	Endpoint   string `json:"endpoint"`
	TurnServer struct {
		Urls     []string `json:"urls"`
		Username string   `json:"username"`
		Password string   `json:"password"`
	} `json:"turnServer"`
}

const vkAuthCacheTTL = 9 * time.Minute // Cache TTL for VK authorization snapshots

// vkAuthSnapshot stores one cached VK authorization result
type vkAuthSnapshot struct {
	MessagesAccessToken string
	AnonymToken         string
	SessionKey          string
	Endpoint            string
	TurnUser            string
	TurnPass            string
	TurnAddr            string
	TurnAddrs           []string
	ExpiresAt           time.Time
}

// vkAuthCacheState tracks cached and in-flight VK authorization requests
var vkAuthCacheState = struct { // Shared VK auth cache and in-flight coordination state
	mu       sync.Mutex
	entries  map[string]vkAuthSnapshot
	inflight map[string]chan struct{}
}{
	entries:  make(map[string]vkAuthSnapshot),
	inflight: make(map[string]chan struct{}),
}

// getCachedVKAuth returns a cached VK auth snapshot when it is still valid
func getCachedVKAuth(key string) (vkAuthSnapshot, bool) {
	now := time.Now()

	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	snapshot, ok := vkAuthCacheState.entries[key]
	if !ok {
		return vkAuthSnapshot{}, false
	}
	if now.After(snapshot.ExpiresAt) {
		delete(vkAuthCacheState.entries, key)
		return vkAuthSnapshot{}, false
	}
	return snapshot, true
}

// putCachedVKAuth stores a VK auth snapshot with a fresh expiration time
func putCachedVKAuth(key string, snapshot vkAuthSnapshot) {
	snapshot.ExpiresAt = time.Now().Add(vkAuthCacheTTL)

	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()
	vkAuthCacheState.entries[key] = snapshot
}

// beginVKAuth registers one in-flight VK auth request and returns its coordination channel
func beginVKAuth(key string) (leader bool, waitCh chan struct{}) {
	vkAuthCacheState.mu.Lock()
	defer vkAuthCacheState.mu.Unlock()

	if ch, ok := vkAuthCacheState.inflight[key]; ok {
		return false, ch
	}

	ch := make(chan struct{})
	vkAuthCacheState.inflight[key] = ch
	return true, ch
}

// endVKAuth releases the in-flight marker for a VK auth request
func endVKAuth(key string) {
	vkAuthCacheState.mu.Lock()
	ch, ok := vkAuthCacheState.inflight[key]
	if ok {
		delete(vkAuthCacheState.inflight, key)
	}
	vkAuthCacheState.mu.Unlock()

	if ok {
		close(ch)
	}
}

// Authorize authorizes with VK and fetches the signaling and TURN session state
func (V *VKHandler) Authorize(callID string, username string) error {
	if strings.TrimSpace(callID) == "" {
		return errors.New("call ID is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}

	normalizedCallID := strings.TrimSpace(callID)
	normalizedCallID = strings.TrimSuffix(normalizedCallID, "/")
	if idx := strings.LastIndex(normalizedCallID, "/call/join/"); idx >= 0 {
		normalizedCallID = normalizedCallID[idx+len("/call/join/"):]
	} else if idx := strings.LastIndex(normalizedCallID, "join/"); idx >= 0 {
		normalizedCallID = normalizedCallID[idx+len("join/"):]
	}

	V.mu.Lock()
	V.ensureInitLocked()
	V.callID = normalizedCallID
	V.joinURL = "https://vk.com/call/join/" + V.callID
	V.username = strings.TrimSpace(username)
	V.mu.Unlock()

	cacheKey := normalizedCallID + "|" + strings.TrimSpace(username)
	for {
		if cached, ok := getCachedVKAuth(cacheKey); ok {
			V.mu.Lock()
			V.ensureInitLocked()
			V.messagesAccessToken = cached.MessagesAccessToken
			V.anonymToken = cached.AnonymToken
			V.sessionKey = cached.SessionKey
			V.endpoint = cached.Endpoint
			V.turnUser = cached.TurnUser
			V.turnPass = cached.TurnPass
			V.turnAddr = cached.TurnAddr
			V.turnAddrs = append([]string(nil), cached.TurnAddrs...)
			V.mu.Unlock()
			slog.Debug("vk authorize reused cached auth state")
			return nil
		}

		leader, waitCh := beginVKAuth(cacheKey)
		if leader {
			defer endVKAuth(cacheKey)
			break
		}

		select {
		case <-waitCh:
			continue
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	messagesToken, anonymToken, err := V.authorizeAnonymous(ctx)
	if err != nil {
		slog.Warn("vk authorize anonymous flow failed", "error", err)
		return err
	}
	V.mu.Lock()
	V.messagesAccessToken = messagesToken
	V.anonymToken = anonymToken
	V.mu.Unlock()

	loginSession, err := V.callsLogin(ctx)
	if err != nil {
		slog.Warn("vk calls login failed", "error", err)
		return err
	}
	V.mu.Lock()
	V.sessionKey = loginSession
	V.mu.Unlock()

	startedInfo, err := V.joinConversation(ctx)
	if err != nil {
		slog.Warn("vk join conversation failed", "error", err)
		return err
	}

	turnAddrs := normalizeTurnAddresses(startedInfo.TurnServer.Urls)
	turnAddr := ""
	if len(turnAddrs) > 0 {
		turnAddr = turnAddrs[0]
	}

	V.mu.Lock()
	V.endpoint = startedInfo.Endpoint
	V.turnUser = startedInfo.TurnServer.Username
	V.turnPass = startedInfo.TurnServer.Password
	V.turnAddr = turnAddr
	V.turnAddrs = append([]string(nil), turnAddrs...)
	snapshot := vkAuthSnapshot{
		MessagesAccessToken: V.messagesAccessToken,
		AnonymToken:         V.anonymToken,
		SessionKey:          V.sessionKey,
		Endpoint:            V.endpoint,
		TurnUser:            V.turnUser,
		TurnPass:            V.turnPass,
		TurnAddr:            V.turnAddr,
		TurnAddrs:           append([]string(nil), V.turnAddrs...),
	}
	V.mu.Unlock()
	putCachedVKAuth(cacheKey, snapshot)
	slog.Info("vk authorize completed", "turn_servers", strings.Join(turnAddrs, ","))
	return nil
}

// authorizeAnonymous performs the VK anonymous auth flow and returns both tokens
// The flow intentionally requests the messages token directly via login.vk.com, matching vk-turn-proxy/client behavior
func (V *VKHandler) authorizeAnonymous(ctx context.Context) (string, string, error) {
	slog.Debug("vk authorize anonymous started")
	messagesResp, err := V.postVKForm(ctx, vkLoginEndpoint+"/?act=get_anonym_token", common.NewValues(
		"client_id", vkClientID,
		"token_type", "messages",
		"client_secret", vkClientSecret,
		"version", "1",
		"app_id", vkClientID,
	), nil)
	if err != nil {
		return "", "", err
	}

	messagesAccessToken, ok := common.NestedString(messagesResp, "data", "access_token")
	if !ok || messagesAccessToken == "" {
		return "", "", errors.New("field data.access_token is missing")
	}
	slog.Debug("vk authorize anonymous messages token acquired")

	anonymToken, err := V.fetchCallAnonymousToken(ctx, messagesAccessToken)
	if err == nil {
		slog.Debug("vk authorize anonymous call token acquired")
	}
	return messagesAccessToken, anonymToken, err
}

// fetchCallAnonymousToken exchanges the messages token for a call-scoped anonymous token
func (V *VKHandler) fetchCallAnonymousToken(ctx context.Context, messagesAccessToken string) (string, error) {
	V.mu.Lock()
	V.ensureInitLocked()
	joinURL := V.joinURL
	username := V.username
	V.mu.Unlock()

	form := common.NewValues(
		"vk_join_link", joinURL,
		"name", username,
		"access_token", messagesAccessToken,
	)

	for attempt := 0; attempt < vkCaptchaRetries; attempt++ {
		resp, err := V.postVKForm(ctx, vkAPIEndpoint+"/calls.getAnonymousToken?v=5.274&client_id="+vkClientID, form, map[string]string{
			"Origin":  "https://vk.com",
			"Referer": "https://vk.com/",
		})
		if err != nil {
			return "", err
		}

		if errMap, ok := resp["error"].(map[string]any); ok {
			apiErr := parseVKAPIError(errMap)
			if apiErr.Code != 14 {
				return "", fmt.Errorf("%s", apiErr.Message)
			}
			slog.Info(
				"vk captcha challenge received",
				"request_attempt",
				attempt+1,
				"max_attempts",
				vkCaptchaRetries,
			)

			solveStartedAt := time.Now()
			successToken, err := V.solveCaptchaWithRetry(ctx, apiErr)
			if err != nil {
				slog.Warn(
					"vk captcha solve failed",
					"duration_ms",
					time.Since(solveStartedAt).Milliseconds(),
					"error",
					err,
				)
				if errors.Is(err, errCaptchaRateLimit) {
					form.Del("captcha_key")
					form.Del("captcha_sid")
					form.Del("success_token")
					form.Del("captcha_ts")
					form.Del("captcha_attempt")
					slog.Info("vk captcha rate limited, retrying", "delay", 5*time.Second)
					select {
					case <-ctx.Done():
						return "", ctx.Err()
					case <-time.After(5 * time.Second):
					}
					continue
				}
				return "", err
			}
			slog.Info(
				"vk captcha solved",
				"duration_ms",
				time.Since(solveStartedAt).Milliseconds(),
				"request_attempt",
				attempt+1,
			)

			form.Set("captcha_key", "")
			form.Set("captcha_sid", apiErr.CaptchaSID)
			form.Set("is_sound_captcha", "0")
			form.Set("success_token", successToken)
			form.Set("captcha_ts", apiErr.CaptchaTS)
			form.Set("captcha_attempt", common.FirstNonEmpty(apiErr.CaptchaAttempt, "1"))
			continue
		}

		token, ok := common.NestedString(resp, "response", "token")
		if !ok || token == "" {
			return "", errors.New("field response.token is missing")
		}
		return token, nil
	}

	return "", errors.New("failed to obtain anonymous call token")
}

// callsLogin creates an anonymous calls session in the VK calls backend
func (V *VKHandler) callsLogin(ctx context.Context) (string, error) {
	sessionData := vkCallsSessionData{
		Version:       2,
		DeviceID:      uuid.NewString(),
		ClientVersion: vkCallsClientVer,
		ClientType:    "SDK_JS",
	}
	sessionDataJSON, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}
	slog.Debug("vk calls login request prepared", "session_data_bytes", len(sessionDataJSON))

	resp, err := V.postVKForm(ctx, vkCallsEndpoint, common.NewValues(
		"method", "auth.anonymLogin",
		"format", "JSON",
		"application_key", vkCallsAppKey,
		"session_data", string(sessionDataJSON),
	), map[string]string{
		"Origin":  "https://vk.com",
		"Referer": "https://vk.com/",
	})
	if err != nil {
		return "", err
	}

	sessionKey, ok := resp["session_key"].(string)
	if !ok || sessionKey == "" {
		return "", fmt.Errorf("unexpected anonym login response: %v", resp)
	}
	slog.Debug("vk calls login completed")
	return sessionKey, nil
}

// joinConversation joins the target call and returns the signaling bootstrap payload
func (V *VKHandler) joinConversation(ctx context.Context) (vkStartedConversationInfo, error) {
	V.mu.Lock()
	V.ensureInitLocked()
	callID := V.callID
	anonymToken := V.anonymToken
	sessionKey := V.sessionKey
	V.mu.Unlock()

	resp, err := V.postVKForm(ctx, vkCallsEndpoint, common.NewValues(
		"method", "vchat.joinConversationByLink",
		"format", "JSON",
		"application_key", vkCallsAppKey,
		"joinLink", callID,
		"isVideo", "false",
		"protocolVersion", "5",
		"capabilities", "2F7F",
		"anonymToken", anonymToken,
		"session_key", sessionKey,
	), map[string]string{
		"Origin":  "https://vk.com",
		"Referer": "https://vk.com/",
	})
	if err != nil {
		return vkStartedConversationInfo{}, err
	}
	info, err := parseStartedConversation(resp)
	if err == nil {
		slog.Debug("vk join conversation completed", "turn_urls_count", len(info.TurnServer.Urls))
	}
	return info, err
}

// parseStartedConversation parses the VK conversation bootstrap payload
func parseStartedConversation(raw map[string]any) (vkStartedConversationInfo, error) {
	payload := raw
	if inner, ok := raw["response"].(map[string]any); ok {
		payload = inner
	}

	var out vkStartedConversationInfo
	out.Endpoint = common.StringifyAny(payload["endpoint"])

	turnRaw, ok := payload["turn_server"].(map[string]any)
	if !ok {
		turnRaw, _ = payload["turnServer"].(map[string]any)
	}
	if ok && turnRaw != nil {
		out.TurnServer.Username = common.StringifyAny(turnRaw["username"])
		out.TurnServer.Password = common.FirstNonEmpty(
			common.StringifyAny(turnRaw["password"]),
			common.StringifyAny(turnRaw["credential"]),
		)
		out.TurnServer.Urls = common.StringSliceAny(turnRaw["urls"])
	}

	return out, nil
}

// normalizeTurnAddresses trims and deduplicates TURN addresses from VK payloads
func normalizeTurnAddresses(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		addr = strings.Split(addr, "?")[0]
		addr = strings.TrimPrefix(addr, "turn:")
		addr = strings.TrimPrefix(addr, "turns:")
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// parseVKAPIError converts a generic VK error payload into a typed error struct
func parseVKAPIError(errMap map[string]any) vkAPIError {
	code, _ := errMap["error_code"].(float64)
	message, _ := errMap["error_msg"].(string)
	redirectURI, _ := errMap["redirect_uri"].(string)
	sessionToken := ""
	adFP := ""
	if redirectURI != "" {
		if parsed, err := url.Parse(redirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
			adFP = common.FirstNonEmpty(parsed.Query().Get("adFp"), parsed.Query().Get("adfp"))
		}
	}
	return vkAPIError{
		Code:           int(code),
		Message:        message,
		CaptchaSID:     common.StringifyAny(errMap["captcha_sid"]),
		CaptchaTS:      common.StringifyAny(errMap["captcha_ts"]),
		CaptchaAttempt: common.StringifyAny(errMap["captcha_attempt"]),
		SessionToken:   sessionToken,
		AdFP:           adFP,
		RedirectURI:    redirectURI,
	}
}
