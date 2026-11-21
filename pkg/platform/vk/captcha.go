package vk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	_ "image/jpeg"
	"log/slog"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	captchaAPIVersion    = "5.131"            // captcha API version
	captchaPageOrigin    = "https://id.vk.ru" // captcha page and API origin
	captchaDefaultDomain = "vk.com"           // captcha domain when the redirect URI does not name one
	captchaParentOrigin  = "https://vk.ru"    // origin of the page that embeds the captcha frame
	captchaSensorsDelay  = 200                // default sensor sampling interval in milliseconds
)

var (
	reCaptchaPowArgs   = regexp.MustCompile(`}\('([^']*)',\s*(\d+)(?:,\s*'([^']*)',\s*(\[[^\]]*\]))?\)\);`)        // extracts PoW input, difficulty, initial error and probe order
	reCaptchaDebugInfo = regexp.MustCompile(`[A-Za-z_$][\w$]*:\s*"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})"`) // extracts the debug_info UUID out of window.vk
	reCaptchaLangID    = regexp.MustCompile(`window\.langConfig\s*=\s*\{"id":(\d+)`)                               // extracts the page language ID
	reCaptchaOracle    = regexp.MustCompile(`new Error\('oracle'\)`)                                               // locates the stack trace probe

	errCaptchaRateLimit = errors.New("captcha session rate limit reached") // marks exhausted captcha sessions
)

// captchaContentSetting represents an available captcha content reference
type captchaContentSetting struct {
	Type        string `json:"type"`         // Content type
	Settings    string `json:"settings"`     // Settings payload
	SettingsKey string `json:"settings_key"` // Settings key
}

// captchaPage stores captcha metadata extracted from the challenge page
type captchaPage struct {
	URL           string   // URL the page was loaded from
	PowInput      string   // proof-of-work input
	PowDifficulty int      // proof-of-work difficulty in leading zeros
	PowError      string   // error the script reports until the proof of work is solved
	ProbeOrder    []string // order the page runs its basic telemetry probes in
	DebugInfo     string   // debug info echoed back to the server
	LangID        string   // page language ID
	OracleLine    int      // line of the stack trace probe
	OracleColumn  int      // column of the stack trace probe, in UTF-16 units
}

// captchaSession stores the state of a single captcha solving session
type captchaSession struct {
	Token        string    // captcha session token
	Domain       string    // captcha domain
	AdFP         string    // ad fingerprint
	BrowserFP    string    // browser fingerprint
	DebugInfo    string    // debug info
	Cookie       string    // cookies the page scripts have set
	PowHash      string    // solved proof-of-work envelope
	PowReadyAt   time.Time // when the page script would have finished the envelope
	SensorsDelay int       // sensor sampling interval in milliseconds
}

// captchaCheck stores the result of a captcha verification attempt
type captchaCheck struct {
	Status       string // check result status
	SuccessToken string // token returned on success
	ShowType     string // next challenge type, if any
	Settings     string // settings for the next challenge
}

// captchaShowTypeError tells solveCaptcha to switch to another solver
type captchaShowTypeError struct {
	ShowType string // challenge type that is not supported
	Settings string // settings of that challenge
}

// Error returns error text
func (e *captchaShowTypeError) Error() string {
	return "captcha show type mismatch: " + e.ShowType
}

// captchaDevice is the device summary reported by componentDone, in the order the page serializes it
type captchaDevice struct {
	ScreenWidth             int      `json:"screenWidth"`
	ScreenHeight            int      `json:"screenHeight"`
	ScreenAvailWidth        int      `json:"screenAvailWidth"`
	ScreenAvailHeight       int      `json:"screenAvailHeight"`
	InnerWidth              int      `json:"innerWidth"`
	InnerHeight             int      `json:"innerHeight"`
	DevicePixelRatio        float64  `json:"devicePixelRatio"`
	Language                string   `json:"language"`
	Languages               []string `json:"languages"`
	Webdriver               bool     `json:"webdriver"`
	HardwareConcurrency     int      `json:"hardwareConcurrency"`
	DeviceMemory            int      `json:"deviceMemory"`
	ConnectionEffectiveType string   `json:"connectionEffectiveType"`
	NotificationsPermission string   `json:"notificationsPermission"`
}

// solveCaptcha loads the captcha page and solves one challenge session
func (V *Handler) solveCaptcha(ctx context.Context, apiErr vkAPIError) (string, error) {
	if apiErr.RedirectURI == "" || apiErr.SessionToken == "" {
		return "", errors.New("unsupported captcha challenge")
	}

	V.rotateBrowserProfile()
	profile := V.browserProfile()

	pageURL, domain := captchaPageURL(apiErr.RedirectURI)

	navigatedAt := time.Now()
	html, err := V.navigateVK(ctx, pageURL, captchaParentOrigin+"/")
	if err != nil {
		return "", err
	}

	page, err := parseCaptchaPage(string(html))
	if err != nil {
		return "", err
	}
	page.URL = pageURL

	session := &captchaSession{
		Token:        apiErr.SessionToken,
		Domain:       domain,
		AdFP:         apiErr.AdFP,
		BrowserFP:    profile.FingerprintID,
		DebugInfo:    page.DebugInfo,
		Cookie:       captchaCookies(profile, common.FirstNonEmpty(page.LangID, captchaLangID(profile))),
		SensorsDelay: captchaSensorsDelay,
	}

	slog.Debug("vk captcha solving pow", "difficulty", page.PowDifficulty)

	session.PowHash, session.PowReadyAt, err = V.buildCaptchaPoW(page, navigatedAt)
	if err != nil {
		return "", fmt.Errorf("captcha pow failed: %w", err)
	}

	slog.Debug("vk captcha pow solved", "debug_info", session.DebugInfo, "ready_in", time.Until(session.PowReadyAt))

	// The widget bundle loads and boots before it opens the session.
	if err := sleepCtx(ctx, randomDuration(350, 750)); err != nil {
		return "", err
	}

	showType, sliderSettings, err := V.initCaptchaSession(ctx, session, page.LangID)
	if err != nil {
		return "", err
	}

	if err := sleepCtx(ctx, randomDuration(20, 150)); err != nil {
		return "", err
	}

	if err := V.captchaSettings(ctx, session); err != nil {
		return "", err
	}

	// The widget renders before it reports componentDone.
	if err := sleepCtx(ctx, randomDuration(250, 600)); err != nil {
		return "", err
	}

	var token string
	for {
		slog.Debug("vk captcha solving", "show_type", showType)

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

	_, _ = V.captchaRequest(ctx, session, "captchaNotRobot.endSession", session.baseValues())
	return token, nil
}

// captchaPageURL returns the URL the browser loads for a redirect URI and the captcha domain it names
func captchaPageURL(redirectURI string) (string, string) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI, captchaDefaultDomain
	}

	domain := common.FirstNonEmpty(parsed.Query().Get("domain"), captchaDefaultDomain)
	if parsed.Query().Has("origin") {
		return redirectURI, domain
	}

	// The embedding page appends its own origin to the frame URL.
	separator := "&"
	if parsed.RawQuery == "" {
		separator = "?"
	}

	return redirectURI + separator + "origin=" + url.QueryEscape(captchaParentOrigin), domain
}

// baseValues returns the parameters every captcha session request starts with
func (s *captchaSession) baseValues() *common.Values {
	return common.NewValues(
		"session_token", s.Token,
		"domain", s.Domain,
		"adFp", s.AdFP,
		"access_token", "",
	)
}

// initCaptchaSession initializes a VK captcha session
func (V *Handler) initCaptchaSession(ctx context.Context, session *captchaSession, langID string) (string, string, error) {
	resp, err := V.captchaRequest(ctx, session, "captchaNotRobot.initSession", common.NewValues(
		"session_token", session.Token,
		"domain", session.Domain,
		"lang", common.FirstNonEmpty(langID, captchaLangID(V.browserProfile())),
		"access_token", "",
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

// captchaLangID returns the captcha language ID matching the profile's primary language
func captchaLangID(p common.BrowserProfile) string {
	if strings.HasPrefix(p.Languages[0], "en") {
		return "3"
	}

	return "0"
}

// captchaCookies returns the cookies the VK page scripts set in a browser with the given profile
func captchaCookies(p common.BrowserProfile, langID string) string {
	cookies := []string{
		"remixlang=" + langID,
		"remixscreen_width=" + strconv.Itoa(p.ScreenWidth),
		"remixscreen_height=" + strconv.Itoa(p.ScreenHeight),
		"remixscreen_dpr=" + strconv.FormatFloat(p.PixelRatio, 'f', -1, 64),
		"remixscreen_depth=24",
		"remixscreen_winzoom=1",
	}

	if p.PrefersDark {
		cookies = append(cookies, "remixdark_color_scheme=1")
	}

	return strings.Join(append(cookies, "remixcolor_scheme_mode=auto", "remixscreen_orient=1"), "; ")
}

// captchaSettings fetches widget settings and picks up the sensor sampling interval
func (V *Handler) captchaSettings(ctx context.Context, session *captchaSession) error {
	resp, err := V.captchaRequest(ctx, session, "captchaNotRobot.settings", session.baseValues())
	if err != nil {
		return fmt.Errorf("captcha settings failed: %w", err)
	}

	if data, ok := resp["response"].(map[string]any); ok {
		if delay, ok := data["sensors_delay"].(float64); ok && delay > 0 {
			session.SensorsDelay = int(delay)
		}
	}

	return nil
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

// parseCaptchaPage extracts captcha metadata from HTML
func parseCaptchaPage(html string) (*captchaPage, error) {
	page := &captchaPage{}

	match := reCaptchaPowArgs.FindStringSubmatch(html)
	if len(match) < 5 {
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
	page.PowError = match[3]

	if match[4] != "" {
		if err := json.Unmarshal([]byte(match[4]), &page.ProbeOrder); err != nil {
			slog.Warn("vk captcha probe order is malformed", "error", err)
		}
	}

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

	if lang := reCaptchaLangID.FindStringSubmatch(html); len(lang) > 1 {
		page.LangID = lang[1]
	}

	page.OracleLine, page.OracleColumn = locateCaptchaOracle(html)
	return page, nil
}

// locateCaptchaOracle returns the position V8 reports for the stack trace probe
func locateCaptchaOracle(html string) (int, int) {
	loc := reCaptchaOracle.FindStringIndex(html)
	if loc == nil {
		slog.Warn("vk captcha stack trace probe not found")
		return 118, 42692
	}

	before := html[:loc[0]]
	lineStart := strings.LastIndexByte(before, '\n') + 1
	column := len(utf16.Encode([]rune(before[lineStart:]))) + 1

	return strings.Count(before, "\n") + 1, column
}

// captchaRequest performs captcha API requests
func (V *Handler) captchaRequest(ctx context.Context, session *captchaSession, method string, form *common.Values) (map[string]any, error) {
	return V.postVKForm(ctx, vkAPIEndpoint+"/"+method+"?v="+captchaAPIVersion, form, map[string]string{
		"Origin":   captchaPageOrigin,
		"Referer":  captchaPageOrigin + "/",
		"Cookie":   session.Cookie,
		"Priority": "u=1, i",
	})
}

// performCaptchaCheck submits captcha answer and returns status payload
func (V *Handler) performCaptchaCheck(ctx context.Context, session *captchaSession, answerJSON string, cursor string) (*captchaCheck, error) {
	if err := waitForCaptchaPoW(ctx, session); err != nil {
		return nil, err
	}

	values := common.NewValues(
		"session_token", session.Token,
		"domain", session.Domain,
		"adFp", session.AdFP,
		"accelerometer", "[]",
		"gyroscope", "[]",
		"motion", "[]",
		"cursor", cursor,
		"taps", "[]",
		"browser_fp", session.BrowserFP,
		"hash", session.PowHash,
		"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON)),
		"debug_info", session.DebugInfo,
		"access_token", "",
	)

	slog.Debug("vk captcha check values", "adFp", session.AdFP, "cursor", cursor, "browser_fp", session.BrowserFP,
		"answer", answerJSON, "debug_info", session.DebugInfo)

	resp, err := V.captchaRequest(ctx, session, "captchaNotRobot.check", values)
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
	p := V.browserProfile()
	device, err := json.Marshal(captchaDevice{
		ScreenWidth:             p.ScreenWidth,
		ScreenHeight:            p.ScreenHeight,
		ScreenAvailWidth:        p.AvailWidth,
		ScreenAvailHeight:       p.AvailHeight,
		InnerWidth:              p.InnerWidth,
		InnerHeight:             p.InnerHeight,
		DevicePixelRatio:        p.PixelRatio,
		Language:                p.Languages[0],
		Languages:               p.Languages,
		HardwareConcurrency:     p.HardwareConcurrency,
		DeviceMemory:            p.DeviceMemory,
		ConnectionEffectiveType: "4g",
		NotificationsPermission: "denied",
	})
	if err != nil {
		return err
	}

	// The browser fingerprint is still being computed when the widget reports in.
	if _, err := V.captchaRequest(ctx, session, "captchaNotRobot.componentDone", common.NewValues(
		"session_token", session.Token,
		"domain", session.Domain,
		"adFp", session.AdFP,
		"browser_fp", "",
		"device", string(device),
		"access_token", "",
	)); err != nil {
		return fmt.Errorf("captcha componentDone failed: %w", err)
	}

	return nil
}

// waitForCaptchaPoW blocks until the page script would have produced its envelope
func waitForCaptchaPoW(ctx context.Context, session *captchaSession) error {
	return sleepCtx(ctx, time.Until(session.PowReadyAt))
}

// sleepCtx sleeps for the given duration unless the context ends first
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// randomDuration returns a random duration between min and max milliseconds
func randomDuration(minMs, maxMs int) time.Duration {
	return time.Duration(minMs+rand.Intn(maxMs-minMs+1)) * time.Millisecond
}
