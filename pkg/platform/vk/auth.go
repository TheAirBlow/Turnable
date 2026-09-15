package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/protocol"
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

// vkCallsError stores an error returned by the VK calls backend
type vkCallsError struct {
	Code    int
	Message string
}

// Error formats the VK calls backend error
func (e *vkCallsError) Error() string {
	return fmt.Sprintf("vk calls error %d: %s", e.Code, e.Message)
}

// checkVKCallsError inspects a VK calls-API JSON response for an error envelope
func checkVKCallsError(resp map[string]any) error {
	if errMap, ok := resp["error"].(map[string]any); ok {
		apiErr := parseVKAPIError(errMap)
		return fmt.Errorf("%w: %w", platform.ErrFatal, &vkCallsError{Code: apiErr.Code, Message: apiErr.Message})
	}
	if code, ok := resp["error_code"].(float64); ok {
		message, _ := resp["error_msg"].(string)
		return fmt.Errorf("%w: %w", platform.ErrFatal, &vkCallsError{Code: int(code), Message: message})
	}
	return nil
}

// isVKCallTokenRejected reports whether err means VK no longer accepts the anonymous call token
func isVKCallTokenRejected(err error) bool {
	var callsErr *vkCallsError
	if !errors.As(err, &callsErr) {
		return false
	}
	return callsErr.Code == 457 || (callsErr.Code == 100 && strings.Contains(callsErr.Message, "anonym_token"))
}

// isVKSessionRejected reports whether err means VK no longer accepts the calls session key
func isVKSessionRejected(err error) bool {
	var callsErr *vkCallsError
	return errors.As(err, &callsErr) && (callsErr.Code == 102 || callsErr.Code == 103)
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

// Authorize authorizes with VK, reusing cached credentials for the call while VK still accepts them
func (V *Handler) Authorize(callID string, username string) error {
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

	V.ensureInit()

	V.mu.Lock()
	V.callID = normalizedCallID
	V.joinURL = "https://vk.com/call/join/" + normalizedCallID
	V.username = strings.TrimSpace(username)
	V.mu.Unlock()

	return V.authorize(false)
}

// authorize loads credentials for the current call, joining it when cached TURN credentials are unusable or an endpoint is required
func (V *Handler) authorize(needEndpoint bool) error {
	V.mu.RLock()
	callID := V.callID
	joinURL := V.joinURL
	name := V.username
	V.mu.RUnlock()

	lock := vkAuthLock(callID)
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if entry, ok := getCachedVKAuth(callID); ok && entry.AnonymToken != "" {
		refreshed := V.refreshMessagesToken(ctx, &entry)
		if !needEndpoint && entry.turnUsable() {
			if refreshed {
				putCachedVKAuth(callID, entry)
			}
			V.applyAuth(entry, "")
			slog.Info("vk authorize reused cached turn credentials")
			return nil
		}

		info, err := V.joinWithEntry(ctx, callID, &entry)
		if err == nil {
			turnAddrs := V.storeAuth(callID, entry, info)
			slog.Info("vk authorize reused cached call token", "turn_servers", strings.Join(turnAddrs, ","))
			return nil
		}
		if !isVKCallTokenRejected(err) {
			slog.Warn("vk join conversation failed", "error", err)
			return err
		}
		slog.Info("vk cached call token rejected, requesting a new one", "error", err)
	}

	messagesToken, anonymToken, err := V.authorizeAnonymous(ctx, joinURL, name)
	if err != nil {
		slog.Warn("vk authorize anonymous flow failed", "error", err)
		return err
	}

	entry := vkAuthEntry{
		Username:            name,
		MessagesAccessToken: messagesToken,
		AnonymToken:         anonymToken,
	}
	info, err := V.joinWithEntry(ctx, callID, &entry)
	if err != nil {
		slog.Warn("vk join conversation failed", "error", err)
		return err
	}

	turnAddrs := V.storeAuth(callID, entry, info)
	slog.Info("vk authorize completed", "turn_servers", strings.Join(turnAddrs, ","))
	return nil
}

// joinWithEntry joins the call with the entry's call token, logging in again when the session key is rejected
func (V *Handler) joinWithEntry(ctx context.Context, callID string, entry *vkAuthEntry) (vkStartedConversationInfo, error) {
	if entry.SessionKey != "" {
		info, err := V.joinConversation(ctx, callID, entry.AnonymToken, entry.SessionKey)
		if !isVKSessionRejected(err) {
			return info, err
		}
		slog.Debug("vk cached session key rejected, logging in again", "error", err)
	}

	sessionKey, err := V.callsLogin(ctx)
	if err != nil {
		return vkStartedConversationInfo{}, err
	}

	entry.SessionKey = sessionKey
	return V.joinConversation(ctx, callID, entry.AnonymToken, sessionKey)
}

// refreshMessagesToken replaces an expired messages token in the entry, reporting whether it changed
func (V *Handler) refreshMessagesToken(ctx context.Context, entry *vkAuthEntry) bool {
	if !messagesTokenExpired(entry.MessagesAccessToken) {
		return false
	}

	token, err := V.fetchMessagesToken(ctx)
	if err != nil {
		slog.Warn("vk messages token refresh failed", "error", err)
		return false
	}

	entry.MessagesAccessToken = token
	return true
}

// storeAuth caches the entry with TURN credentials from the join response and applies it to the handler
func (V *Handler) storeAuth(callID string, entry vkAuthEntry, info vkStartedConversationInfo) []string {
	turnAddrs := normalizeTurnAddresses(info.TurnServer.Urls)
	entry.TURNInfos = make([]protocol.TURNInfo, len(turnAddrs))
	for i, addr := range turnAddrs {
		entry.TURNInfos[i] = protocol.TURNInfo{
			Address:  addr,
			Username: info.TurnServer.Username,
			Password: info.TurnServer.Password,
		}
	}

	putCachedVKAuth(callID, entry)
	V.applyAuth(entry, info.Endpoint)
	return turnAddrs
}

// applyAuth loads cached credentials and the signaling endpoint into the handler
func (V *Handler) applyAuth(entry vkAuthEntry, endpoint string) {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.username = entry.Username
	V.messagesAccessToken = entry.MessagesAccessToken
	V.anonymToken = entry.AnonymToken
	V.sessionKey = entry.SessionKey
	V.endpoint = endpoint
	V.turnInfos = entry.TURNInfos
}

// authorizeAnonymous performs the full VK anonymous auth flow, returning the messages token and call token
func (V *Handler) authorizeAnonymous(ctx context.Context, joinURL, username string) (string, string, error) {
	if os.Getenv("VK_FORCE_MANUAL") == "1" {
		slog.Info("vk captcha manual solve forced")
		return V.solveManualCaptcha(ctx, joinURL)
	}

	slog.Debug("vk authorize anonymous started")

	var (
		messagesToken string
		form          *common.Values
	)

	for attempt := 0; attempt < vkCaptchaRetries; attempt++ {
		if messagesToken == "" {
			token, err := V.fetchMessagesToken(ctx)
			if err != nil {
				return "", "", err
			}

			messagesToken = token
			form = common.NewValues(
				"vk_join_link", joinURL,
				"name", username,
				"access_token", messagesToken,
			)
		}

		resp, err := V.postVKForm(ctx, vkAPIEndpoint+"/calls.getAnonymousToken?v=5.274&client_id="+vkClientID, form, map[string]string{
			"Origin":  "https://vk.com",
			"Referer": "https://vk.com/",
		})
		if err != nil {
			return "", "", err
		}

		if errMap, ok := resp["error"].(map[string]any); ok {
			apiErr := parseVKAPIError(errMap)
			if apiErr.Code != 14 {
				return "", "", fmt.Errorf("%w: vk api error %d: %s", platform.ErrFatal, apiErr.Code, apiErr.Message)
			}
			slog.Info("vk captcha challenge received", "request_attempt", attempt+1, "max_attempts", vkCaptchaRetries)

			solveStartedAt := time.Now()
			successToken, solveErr := V.solveCaptcha(ctx, apiErr)

			if solveErr != nil {
				slog.Warn("vk captcha solve failed", "duration_ms", time.Since(solveStartedAt).Milliseconds(), "error", solveErr)
				if errors.Is(solveErr, errCaptchaRateLimit) {
					slog.Info("vk captcha rate limited, retrying", "delay", 60*time.Second)
					select {
					case <-ctx.Done():
						return "", "", ctx.Err()
					case <-time.After(60 * time.Second):
					}
				}

				messagesToken = ""
				continue
			}

			slog.Info("vk captcha solved", "duration_ms", time.Since(solveStartedAt).Milliseconds(), "request_attempt", attempt+1)
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
			return "", "", fmt.Errorf("%w: field response.token is missing", platform.ErrFatal)
		}

		slog.Debug("vk authorize anonymous call token acquired")
		return messagesToken, token, nil
	}

	slog.Info("all auto captcha attempts exhausted, falling back to manual solve")
	return V.solveManualCaptcha(ctx, joinURL)
}

// fetchMessagesToken requests a new anonymous messages token
func (V *Handler) fetchMessagesToken(ctx context.Context) (string, error) {
	resp, err := V.postVKForm(ctx, vkLoginEndpoint+"/?act=get_anonym_token", common.NewValues(
		"client_id", vkClientID,
		"token_type", "messages",
		"client_secret", vkClientSecret,
		"version", "1",
		"app_id", vkClientID,
	), nil)
	if err != nil {
		return "", err
	}

	token, ok := common.NestedString(resp, "data", "access_token")
	if !ok || token == "" {
		return "", fmt.Errorf("%w: field data.access_token is missing", platform.ErrFatal)
	}

	slog.Debug("vk anonymous messages token acquired")
	return token, nil
}

// callsLogin creates an anonymous calls session in the VK calls backend
func (V *Handler) callsLogin(ctx context.Context) (string, error) {
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
	if err := checkVKCallsError(resp); err != nil {
		return "", err
	}

	sessionKey, ok := resp["session_key"].(string)
	if !ok || sessionKey == "" {
		return "", fmt.Errorf("%w: unexpected anonym login response: %v", platform.ErrFatal, resp)
	}
	slog.Debug("vk calls login completed")
	return sessionKey, nil
}

// joinConversation joins the target call and returns the signaling bootstrap payload
func (V *Handler) joinConversation(ctx context.Context, callID, anonymToken, sessionKey string) (vkStartedConversationInfo, error) {
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
	if err := checkVKCallsError(resp); err != nil {
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
