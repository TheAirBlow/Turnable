package vk

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	_ "image/jpeg"
	"log/slog"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	http "github.com/useflyent/fhttp"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	captchaAPIVersion = "5.131"            // captcha API version
	captchaPageOrigin = "https://id.vk.ru" // captcha page and API origin
	captchaDomain     = "vk.ru"            // captcha challenge domain
)

var (
	deviceInfo = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1080,"innerWidth":1920,"innerHeight":951,"devicePixelRatio":1,"language":"en-US","languages":["en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"denied"}`

	reCaptchaPowArgs   = regexp.MustCompile(`}\('([^"]*)',\s*(\d+)`)                                               // extracts PoW input and difficulty from captcha HTML
	reCaptchaDebugInfo = regexp.MustCompile(`[A-Za-z_$][\w$]*:\s*"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})"`) // extracts the debug_info UUID out of window.vk

	errCaptchaRateLimit = errors.New("captcha session rate limit reached") // marks exhausted captcha sessions
)

// captchaContentSetting represents an available captcha content reference
type captchaContentSetting struct {
	Type        string `json:"type"`
	Settings    string `json:"settings"`
	SettingsKey string `json:"settings_key"`
}

// captchaPage stores captcha metadata extracted from the challenge page
type captchaPage struct {
	PowInput      string
	PowDifficulty int
	DebugInfo     string
}

// captchaSession stores the state of a single captcha solving session
type captchaSession struct {
	Token     string
	AdFP      string
	BrowserFP string
	DebugInfo string
	PowHash   string
}

// captchaCheck stores the result of a captcha verification attempt
type captchaCheck struct {
	Status       string
	SuccessToken string
	ShowType     string
	Settings     string
}

// captchaShowTypeError tells solveCaptcha to switch to another solver
type captchaShowTypeError struct {
	ShowType string
	Settings string
}

// Error returns error text
func (e *captchaShowTypeError) Error() string {
	return "captcha show type mismatch: " + e.ShowType
}

// solveCaptcha fetches the captcha page and solves one challenge session
func (V *Handler) solveCaptcha(ctx context.Context, apiErr vkAPIError) (string, error) {
	if apiErr.RedirectURI == "" || apiErr.SessionToken == "" {
		return "", errors.New("unsupported captcha challenge")
	}

	html, err := V.fetchCaptchaHTML(ctx, apiErr.RedirectURI)
	if err != nil {
		return "", err
	}

	page, err := parseCaptchaPage(html)
	if err != nil {
		return "", err
	}

	session := &captchaSession{
		Token:     apiErr.SessionToken,
		AdFP:      apiErr.AdFP,
		BrowserFP: randomBrowserFP(),
		DebugInfo: page.DebugInfo,
	}

	slog.Debug("vk captcha solving pow", "difficulty", page.PowDifficulty)

	session.PowHash, err = V.buildCaptchaPoW(page)
	if err != nil {
		return "", fmt.Errorf("captcha pow failed: %w", err)
	}

	slog.Debug("vk captcha pow solved", "debug_info", session.DebugInfo)

	base := common.NewValues(
		"session_token", session.Token,
		"domain", captchaDomain,
		"adFp", session.AdFP,
		"access_token", "",
	)

	showType, sliderSettings, err := V.initCaptchaSession(ctx, session)
	if err != nil {
		return "", err
	}

	_, err = V.captchaRequest(ctx, "captchaNotRobot.settings", base)
	if err != nil {
		return "", fmt.Errorf("captcha settings failed: %w", err)
	}

	var token string
	for {
		slog.Info("vk captcha solving", "show_type", showType)

		switch showType {
		case "slider":
			token, err = V.solveSliderCaptcha(ctx, session, sliderSettings)
		case "checkbox":
			token, err = V.solveCheckboxCaptcha(ctx, session)
		default:
			return "", fmt.Errorf("unsupported captcha type: %s", showType)
		}

		if err == nil {
			break
		}

		var showTypeErr *captchaShowTypeError
		if !errors.As(err, &showTypeErr) || showTypeErr.ShowType == "" {
			return "", err
		}

		showType = showTypeErr.ShowType
		sliderSettings = common.FirstNonEmpty(showTypeErr.Settings, sliderSettings)
	}

	_, _ = V.captchaRequest(ctx, "captchaNotRobot.endSession", base)
	return token, nil
}

// initCaptchaSession initializes a VK captcha session.
func (V *Handler) initCaptchaSession(ctx context.Context, session *captchaSession) (string, string, error) {
	resp, err := V.captchaRequest(ctx, "captchaNotRobot.initSession", common.NewValues(
		"session_token", session.Token,
		"domain", captchaDomain,
		"lang", "0",
	))
	if err != nil {
		return "", "", fmt.Errorf("captcha initSession failed: %w", err)
	}

	data, ok := resp["response"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("invalid captcha initSession response: %v", resp)
	}

	showType := common.StringifyAny(data["show_captcha_type"])
	settings := parseCaptchaSettings(data["content_settings"])
	if showType == "slider" && settings == "" {
		return "", "", errors.New("failed to find slider captcha settings")
	}

	slog.Debug("vk captcha session started", "show_type", showType)
	return showType, settings, nil
}

// parseCaptchaSettings picks the slider content reference out of a content_settings array
func parseCaptchaSettings(raw any) string {
	data, err := json.Marshal(raw)
	if err != nil {
		return ""
	}

	var settings []captchaContentSetting
	if json.Unmarshal(data, &settings) != nil {
		return ""
	}

	for _, setting := range settings {
		if setting.Type == "slider" {
			return strings.TrimSpace(common.FirstNonEmpty(setting.SettingsKey, setting.Settings))
		}
	}

	return ""
}

// fetchCaptchaHTML downloads the captcha HTML page from redirect URI
func (V *Handler) fetchCaptchaHTML(ctx context.Context, redirectURI string) (string, error) {
	body, err := V.postVKFormRaw(ctx, http.MethodGet, redirectURI, nil, map[string]string{
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "cross-site",
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseCaptchaPage extracts captcha metadata from HTML
func parseCaptchaPage(html string) (*captchaPage, error) {
	page := &captchaPage{}

	match := reCaptchaPowArgs.FindStringSubmatch(html)
	if len(match) < 3 {
		return nil, errors.New("captcha pow arguments not found")
	}

	difficulty, err := strconv.Atoi(match[2])
	if err != nil || difficulty <= 0 {
		return nil, fmt.Errorf("invalid captcha difficulty %q", match[2])
	}

	if match[1] == "" {
		return nil, errors.New("captcha pow input is empty")
	}

	page.PowInput = match[1]
	page.PowDifficulty = difficulty

	matches := reCaptchaDebugInfo.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil, errors.New("captcha debug info not found")
	}

	if len(matches) > 1 {
		slog.Warn("vk captcha found multiple debug info candidates", "count", len(matches))
	}

	page.DebugInfo = matches[0][1]

	if page.DebugInfo == "" {
		return nil, errors.New("captcha debug info is empty")
	}

	return page, nil
}

// randomBrowserFP generates a random fingerprint
func randomBrowserFP() string {
	r := rand.New(rand.NewSource(rand.Int63()))
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	return hex.EncodeToString(b)
}

// captchaRequest performs captcha API requests
func (V *Handler) captchaRequest(ctx context.Context, method string, form *common.Values) (map[string]any, error) {
	return V.postVKForm(ctx, vkAPIEndpoint+"/"+method+"?v="+captchaAPIVersion, form, map[string]string{
		"Origin":   captchaPageOrigin,
		"Referer":  captchaPageOrigin + "/",
		"Priority": "u=1, i",
	})
}

// performCaptchaCheck submits captcha answer and returns status payload
func (V *Handler) performCaptchaCheck(ctx context.Context, session *captchaSession, answerJSON string, cursor string) (*captchaCheck, error) {
	values := common.NewValues(
		"session_token", session.Token,
		"domain", captchaDomain,
		"adFp", session.AdFP,
		"accelerometer", "[]",
		"gyroscope", "[]",
		"motion", "[]",
		"cursor", cursor,
		"taps", "[]",
		"connectionRtt", "[]",
		"connectionDownlink", "[]",
		"browser_fp", session.BrowserFP,
		"hash", session.PowHash,
		"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON)),
		"debug_info", session.DebugInfo,
		"access_token", "",
	)

	slog.Debug("vk captcha check values", "adFp", session.AdFP, "cursor", cursor, "browser_fp", session.BrowserFP,
		"hash", session.PowHash, "answer", answerJSON, "debug_info", session.DebugInfo)

	resp, err := V.captchaRequest(ctx, "captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("captcha check failed: %w", err)
	}

	check, err := parseCaptchaCheck(resp)
	if err != nil {
		return nil, err
	}

	slog.Debug("vk captcha check response", "status", check.Status)
	return check, nil
}

// parseCaptchaCheck validates and decodes captcha check response
func parseCaptchaCheck(raw map[string]any) (*captchaCheck, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid captcha check response: %v", raw)
	}

	out := &captchaCheck{
		Status:       common.StringifyAny(resp["status"]),
		SuccessToken: common.StringifyAny(resp["success_token"]),
		ShowType:     common.StringifyAny(resp["show_captcha_type"]),
		Settings:     parseCaptchaSettings(resp["content_settings"]),
	}
	if out.Status == "" {
		return nil, fmt.Errorf("captcha check status missing: %v", raw)
	}

	return out, nil
}

// captchaComponentDone reports that the captcha widget has finished rendering
func (V *Handler) captchaComponentDone(ctx context.Context, session *captchaSession) error {
	if _, err := V.captchaRequest(ctx, "captchaNotRobot.componentDone", common.NewValues(
		"session_token", session.Token,
		"domain", captchaDomain,
		"adFp", session.AdFP,
		"browser_fp", session.BrowserFP,
		"device", deviceInfo,
		"access_token", "",
	)); err != nil {
		return fmt.Errorf("captcha componentDone failed: %w", err)
	}

	return nil
}
