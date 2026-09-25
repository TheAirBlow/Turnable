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

// Authorize authorizes with VK, always requesting fresh credentials
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
	V.joinURL = "https://vk.ru/call/join/" + normalizedCallID
	V.username = strings.TrimSpace(username)
	V.mu.Unlock()

	return V.authorize()
}

// authorize runs the full anonymous auth flow and joins the call, loading fresh credentials and the signaling endpoint into the handler
func (V *Handler) authorize() error {
	V.mu.RLock()
	callID := V.callID
	joinURL := V.joinURL
	name := V.username
	V.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	messagesToken, anonymToken, err := V.authorizeAnonymous(ctx, joinURL, name)
	if err != nil {
		slog.Warn("vk authorize anonymous flow failed", "error", err)
		return err
	}

	sessionKey, err := V.callsLogin(ctx)
	if err != nil {
		slog.Warn("vk calls login failed", "error", err)
		return err
	}

	info, err := V.joinConversation(ctx, callID, anonymToken, sessionKey)
	if err != nil {
		slog.Warn("vk join conversation failed", "error", err)
		return err
	}

	turnAddrs := normalizeTurnAddresses(info.TurnServer.Urls)
	turnInfos := make([]protocol.TURNInfo, len(turnAddrs))
	for i, addr := range turnAddrs {
		turnInfos[i] = protocol.TURNInfo{
			Address:  addr,
			Username: info.TurnServer.Username,
			Password: info.TurnServer.Password,
		}
	}

	V.mu.Lock()
	V.messagesAccessToken = messagesToken
	V.anonymToken = anonymToken
	V.sessionKey = sessionKey
	V.endpoint = info.Endpoint
	V.turnInfos = turnInfos
	V.mu.Unlock()

	slog.Info("vk authorize completed", "turn_servers", strings.Join(turnAddrs, ","))
	return nil
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
			"Origin":  "https://vk.ru",
			"Referer": "https://vk.ru/",
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
		"Origin":  "https://vk.ru",
		"Referer": "https://vk.ru/",
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
		"Origin":  "https://vk.ru",
		"Referer": "https://vk.ru/",
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
