package vk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/theairblow/turnable/pkg/common"
)

// solveCheckboxCaptcha solves the checkbox captcha variant
func (V *Handler) solveCheckboxCaptcha(ctx context.Context, session *captchaSession) (string, error) {
	if err := V.captchaComponentDone(ctx, session); err != nil {
		return "", err
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(time.Duration(400+rand.Intn(250)) * time.Millisecond):
	}

	cursor := "[]"

	check, err := V.performCaptchaCheck(ctx, session, "{}", cursor)
	if err != nil {
		return "", err
	}

	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		return "", &captchaShowTypeError{ShowType: check.ShowType, Settings: check.Settings}
	}

	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaRateLimit
	}

	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("checkbox captcha rejected with status %s", check.Status)
	}

	if check.SuccessToken == "" {
		return "", errors.New("captcha success token not found")
	}

	return check.SuccessToken, nil
}

// captchaPowResult is the V2 proof-of-work captcha result
type captchaPowResult struct {
	Hash       string          `json:"hash"`        // Proof-of-work hash
	Nonce      int             `json:"nonce"`       // Nonce that solves the proof of work
	DurationMs int64           `json:"duration_ms"` // Time spent solving, in milliseconds
	Telemetry  json.RawMessage `json:"telemetry"`   // Browser telemetry sent with the solution
	TelHash    string          `json:"tel_hash"`    // Hash of the telemetry
}

// buildCaptchaPoW solves the challenge and assembles the envelope submitted as the hash field
func (V *Handler) buildCaptchaPoW(page *captchaPage) (string, error) {
	hash, nonce := solveCaptchaPoW(page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("no solution found")
	}

	telemetry, err := marshalCaptchaJSON(V.captchaTelemetry())
	if err != nil {
		return "", fmt.Errorf("failed to encode telemetry: %w", err)
	}

	telHash, err := hashCaptchaTelemetry(telemetry)
	if err != nil {
		return "", fmt.Errorf("failed to hash telemetry: %w", err)
	}

	envelope, err := marshalCaptchaJSON(captchaPowResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: captchaPowDuration(nonce),
		Telemetry:  telemetry,
		TelHash:    telHash,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode envelope: %w", err)
	}

	return "v2." + base64.StdEncoding.EncodeToString(envelope), nil
}

// solveCaptchaPoW brute-forces SHA-256 hash prefix target for PoW captcha
func solveCaptchaPoW(input string, difficulty int) (string, int) {
	if input == "" || difficulty <= 0 {
		return "", 0
	}

	target := strings.Repeat("0", difficulty)
	for nonce := 0; nonce <= 10_000_000; nonce++ {
		sum := sha256.Sum256([]byte(input + strconv.Itoa(nonce)))
		hash := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hash, target) {
			return hash, nonce
		}
	}

	return "", 0
}

// captchaProbe wraps the result of a single telemetry probe
type captchaProbe struct {
	OK     bool `json:"ok"`     // Probe completed without error
	Result any  `json:"result"` // Probe result
}

// captchaTelemetry holds every probe the PoW script runs, in the order it runs them
type captchaTelemetry struct {
	Globals          captchaProbe `json:"globals"`            // Global object checks
	UA               captchaProbe `json:"ua"`                 // User agent checks
	Frame            captchaProbe `json:"frame"`              // Frame embedding checks
	MatchMedia       captchaProbe `json:"match_media"`        // Media query checks
	Plugins          captchaProbe `json:"plugins"`            // Plugin list checks
	NavTamper        captchaProbe `json:"nav_tamper"`         // Navigator tampering checks
	Referrer         captchaProbe `json:"referrer"`           // Referrer checks
	DevTools         captchaProbe `json:"devtools"`           // Developer tools checks
	CSS              captchaProbe `json:"css"`                // CSS support checks
	NativeIntegrity  captchaProbe `json:"native_integrity"`   // Native function integrity checks
	CookieTest       captchaProbe `json:"cookie_test"`        // Cookie write check
	AncestorOrigins  captchaProbe `json:"ancestor_origins"`   // Ancestor origin checks
	SandboxBehavior  captchaProbe `json:"sandbox_behavior"`   // Sandbox behavior checks
	MaxTouchPoints   captchaProbe `json:"max_touch_points"`   // Touch point checks
	TimezoneLocale   captchaProbe `json:"timezone_locale"`    // Timezone and locale checks
	DevicePixelRatio captchaProbe `json:"device_pixel_ratio"` // Display density checks
}

// captchaGlobalsProbe reports which globals a browser is expected to expose
type captchaGlobalsProbe struct {
	Doc          bool `json:"doc"`           // Document object present
	Win          bool `json:"win"`           // Window object present
	Nav          bool `json:"nav"`           // Navigator object present
	Webdriver    bool `json:"webdriver"`     // Webdriver flag set
	Subtle       bool `json:"subtle"`        // SubtleCrypto available
	Secure       bool `json:"secure"`        // Secure context
	GCS          bool `json:"gcs"`           // getComputedStyle available
	RAF          bool `json:"raf"`           // requestAnimationFrame available
	Wasm         bool `json:"wasm"`          // WebAssembly available
	PluginsLen   int  `json:"plugins_len"`   // Number of plugins
	LanguagesLen int  `json:"languages_len"` // Number of languages
	HW           int  `json:"hw"`            // Hardware concurrency
	Mem          int  `json:"mem"`           // Device memory in GB
}

// captchaUAProbe reports the user agent and its structured client hints counterpart
type captchaUAProbe struct {
	UserAgent     string              `json:"userAgent"`     // User agent string
	UserAgentData *captchaUADataProbe `json:"userAgentData"` // User agent client hints
}

// captchaUADataProbe reports navigator.userAgentData
type captchaUADataProbe struct {
	Brands       []common.BrowserBrand `json:"brands"`       // Browser brands
	Platform     string                `json:"platform"`     // Platform name
	Mobile       bool                  `json:"mobile"`       // Mobile device
	Architecture *string               `json:"architecture"` // CPU architecture, if reported
}

// captchaFrameProbe reports whether the captcha runs inside a frame
type captchaFrameProbe struct {
	FrameElement       *string `json:"frameElement"`       // Frame element, nil when top-level
	AncestorOriginsLen int     `json:"ancestorOriginsLen"` // Number of ancestor origins
	ParentAccessible   bool    `json:"parentAccessible"`   // Parent frame is accessible
}

// captchaMatchMediaProbe reports the media queries a browser resolves
type captchaMatchMediaProbe struct {
	PrefersDark   bool `json:"prefersDark"`   // Prefers a dark color scheme
	PrefersLight  bool `json:"prefersLight"`  // Prefers a light color scheme
	ReducedMotion bool `json:"reducedMotion"` // Prefers reduced motion
	PointerFine   bool `json:"pointerFine"`   // Has a fine pointer
}

// captchaPluginsProbe reports navigator.plugins
type captchaPluginsProbe struct {
	Length       int        `json:"length"`       // Number of plugins
	Names        []string   `json:"names"`        // Plugin names
	Descriptions []string   `json:"descriptions"` // Plugin descriptions
	MimeTypes    [][]string `json:"mimeTypes"`    // MIME types per plugin
	IsChrome     bool       `json:"isChrome"`     // Plugin list matches Chrome
}

// captchaNavTamperProbe reports whether anything has been patched over the DOM
type captchaNavTamperProbe struct {
	Tampered       bool   `json:"tampered"`         // Navigator looks tampered with
	ElCtor         string `json:"el_ctor"`          // Element constructor name
	StyleCtor      string `json:"style_ctor"`       // Style declaration constructor name
	NavCtor        string `json:"nav_ctor"`         // Navigator constructor name
	AlertNative    bool   `json:"alert_native"`     // alert is native
	ToStringNative bool   `json:"to_string_native"` // toString is native
}

// captchaReferrerProbe reports where the captcha page was navigated from
type captchaReferrerProbe struct {
	Referrer string `json:"referrer"` // Document referrer
	InIframe bool   `json:"inIframe"` // Running inside an iframe
	Domain   string `json:"domain"`   // Document domain
}

// captchaDevToolsProbe reports whether developer tools are open
type captchaDevToolsProbe struct {
	Open    bool `json:"open"`     // Developer tools appear open
	DelayMs int  `json:"delay_ms"` // Detection delay in milliseconds
}

// captchaCSSProbe reports how many expected stylesheet rules are missing
type captchaCSSProbe struct {
	ExpectedMissing int `json:"expectedMissing"` // Count of CSS features expected to be missing
}

// captchaNativeIntegrityProbe reports whether builtins are still native code
type captchaNativeIntegrityProbe struct {
	ProtoMatch             bool `json:"protoMatch"`             // Prototypes match native ones
	XHRNative              bool `json:"xhrNative"`              // XMLHttpRequest is native
	XHRSendNative          bool `json:"xhrSendNative"`          // XMLHttpRequest.send is native
	AddEventListenerNative bool `json:"addEventListenerNative"` // addEventListener is native
	AlertNative            bool `json:"alertNative"`            // alert is native
	ToStringNative         bool `json:"toStringNative"`         // toString is native
}

// captchaCookieTestProbe reports whether cookies can be written
type captchaCookieTestProbe struct {
	Write bool `json:"write"` // Cookie could be written
}

// captchaAncestorOriginsProbe reports the origin that embedded the captcha page
type captchaAncestorOriginsProbe struct {
	AncestorOrigin *string `json:"ancestorOrigin"` // First ancestor origin, if any
}

// captchaSandboxBehaviorProbe reports whether the page runs sandboxed
type captchaSandboxBehaviorProbe struct {
	OriginIsNull   bool `json:"originIsNull"`   // Origin is null
	LocalStorage   bool `json:"localStorage"`   // localStorage is accessible
	SessionStorage bool `json:"sessionStorage"` // sessionStorage is accessible
}

// captchaMaxTouchPointsProbe reports the touch point count of the device
type captchaMaxTouchPointsProbe struct {
	MaxTouchPoints int `json:"maxTouchPoints"` // Maximum touch points
}

// captchaTimezoneLocaleProbe reports the timezone and languages of the device
type captchaTimezoneLocaleProbe struct {
	Timezone  string   `json:"timezone"`  // IANA timezone
	Languages []string `json:"languages"` // Preferred languages
}

// captchaDevicePixelRatioProbe reports the pixel ratio and orientation of the screen
type captchaDevicePixelRatioProbe struct {
	DPR              float64 `json:"dpr"`              // Device pixel ratio
	Orientation      string  `json:"orientation"`      // Screen orientation type
	OrientationAngle int     `json:"orientationAngle"` // Screen orientation angle
}

// captchaPowDuration approximates how long a browser would have spent on the challenge
func captchaPowDuration(nonce int) int64 {
	return max(int64(math.Round(float64(nonce+1)*0.015)), 1)
}

// hashCaptchaTelemetry generates the telemetry hash
func hashCaptchaTelemetry(telemetry []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(telemetry, &decoded); err != nil {
		return "", err
	}

	canonical, err := marshalCaptchaJSON(decoded)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// marshalCaptchaJSON encodes a value the way JSON.stringify would, without HTML escaping
func marshalCaptchaJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}

	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// captchaProbeDone marks a probe as successfully collected
func captchaProbeDone(result any) captchaProbe {
	return captchaProbe{OK: true, Result: result}
}

// captchaTelemetry generates a plausible telemetry blob
func (V *Handler) captchaTelemetry() captchaTelemetry {
	profile := V.profile
	mobile := profile.IsMobile()
	plugins := captchaPlugins(profile)

	return captchaTelemetry{
		Globals: captchaProbeDone(captchaGlobalsProbe{
			Doc:          true,
			Win:          true,
			Nav:          true,
			Subtle:       true,
			Secure:       true,
			GCS:          true,
			RAF:          true,
			Wasm:         true,
			PluginsLen:   plugins.Length,
			LanguagesLen: len(common.BrowserLanguages),
			HW:           common.BrowserHardwareConcurrency,
			Mem:          common.BrowserDeviceMemory,
		}),
		UA: captchaProbeDone(captchaUAProbe{
			UserAgent: profile.UserAgent,
			UserAgentData: &captchaUADataProbe{
				Brands:   profile.Brands(),
				Platform: profile.PlatformName(),
				Mobile:   mobile,
			},
		}),
		Frame: captchaProbeDone(captchaFrameProbe{
			ParentAccessible: true,
		}),
		MatchMedia: captchaProbeDone(captchaMatchMediaProbe{
			PrefersLight: true,
			PointerFine:  !mobile,
		}),
		Plugins: captchaProbeDone(plugins),
		NavTamper: captchaProbeDone(captchaNavTamperProbe{
			ElCtor:         "HTMLDivElement",
			StyleCtor:      "CSSStyleDeclaration",
			NavCtor:        "Navigator",
			AlertNative:    true,
			ToStringNative: true,
		}),
		Referrer: captchaProbeDone(captchaReferrerProbe{
			Referrer: "https://" + captchaDomain + "/",
			Domain:   strings.TrimPrefix(captchaPageOrigin, "https://"),
		}),
		DevTools: captchaProbeDone(captchaDevToolsProbe{}),
		CSS:      captchaProbeDone(captchaCSSProbe{}),
		NativeIntegrity: captchaProbeDone(captchaNativeIntegrityProbe{
			ProtoMatch:             true,
			XHRNative:              true,
			XHRSendNative:          true,
			AddEventListenerNative: true,
			AlertNative:            true,
			ToStringNative:         true,
		}),
		CookieTest: captchaProbeDone(captchaCookieTestProbe{
			Write: true,
		}),
		AncestorOrigins: captchaProbeDone(captchaAncestorOriginsProbe{}),
		SandboxBehavior: captchaProbeDone(captchaSandboxBehaviorProbe{
			LocalStorage:   true,
			SessionStorage: true,
		}),
		MaxTouchPoints: captchaProbeDone(captchaMaxTouchPointsProbe{
			MaxTouchPoints: profile.MaxTouchPoints(),
		}),
		TimezoneLocale: captchaProbeDone(captchaTimezoneLocaleProbe{
			Timezone:  common.BrowserTimezone,
			Languages: common.BrowserLanguages,
		}),
		DevicePixelRatio: captchaProbeDone(captchaDevicePixelRatioProbe{
			DPR:         common.BrowserDevicePixelRatio,
			Orientation: profile.Orientation(),
		}),
	}
}

// captchaPlugins flattens the plugin list of a profile into the shape the probe reports it in
func captchaPlugins(profile common.BrowserProfile) captchaPluginsProbe {
	plugins := profile.Plugins()
	probe := captchaPluginsProbe{
		Length:       len(plugins),
		Names:        make([]string, len(plugins)),
		Descriptions: make([]string, len(plugins)),
		MimeTypes:    make([][]string, len(plugins)),
		IsChrome:     true,
	}

	for i, plugin := range plugins {
		probe.Names[i] = plugin.Name
		probe.Descriptions[i] = plugin.Description
		probe.MimeTypes[i] = plugin.MimeTypes
	}

	return probe
}
