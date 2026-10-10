package common

import (
	"math/rand"
	"regexp"
	"strings"
)

const (
	BrowserHardwareConcurrency = 8               // navigator.hardwareConcurrency
	BrowserDeviceMemory        = 8               // navigator.deviceMemory in GB
	BrowserDevicePixelRatio    = 1.0             // window.devicePixelRatio
	BrowserTimezone            = "Europe/Moscow" // IANA timezone
)

// BrowserLanguages is navigator.languages every profile in the pool reports
var BrowserLanguages = []string{"en-US", "en"}

// reBrowserBrand matches a single brand entry of the Sec-CH-UA header
var reBrowserBrand = regexp.MustCompile(`"([^"]+)";v="([^"]+)"`)

// BrowserProfile holds browser identity headers
type BrowserProfile struct {
	UserAgent       string // User-Agent header
	SecChUa         string // Sec-CH-UA header
	SecChUaMobile   string // Sec-CH-UA-Mobile header
	SecChUaPlatform string // Sec-CH-UA-Platform header
}

// BrowserBrand holds a single navigator.userAgentData brand entry
type BrowserBrand struct {
	Brand   string `json:"brand"`   // Brand name
	Version string `json:"version"` // Major version
}

// BrowserPlugin holds a single navigator.plugins entry
type BrowserPlugin struct {
	Name        string   // plugin name
	Description string   // plugin description
	MimeTypes   []string // supported MIME types
}

// chromePDFMimeTypes is what every entry of the Chrome PDF viewer plugin list handles
var chromePDFMimeTypes = []string{"application/pdf", "text/pdf"}

// chromePlugins is the plugin list desktop Chrome reports; all five are aliases of its bundled PDF viewer
var chromePlugins = []BrowserPlugin{
	{Name: "PDF Viewer", Description: "Portable Document Format", MimeTypes: chromePDFMimeTypes},
	{Name: "Chrome PDF Viewer", Description: "Portable Document Format", MimeTypes: chromePDFMimeTypes},
	{Name: "Chromium PDF Viewer", Description: "Portable Document Format", MimeTypes: chromePDFMimeTypes},
	{Name: "Microsoft Edge PDF Viewer", Description: "Portable Document Format", MimeTypes: chromePDFMimeTypes},
	{Name: "WebKit built-in PDF", Description: "Portable Document Format", MimeTypes: chromePDFMimeTypes},
}

// IsMobile reports whether this profile describes a mobile browser
func (p BrowserProfile) IsMobile() bool {
	return p.SecChUaMobile == "?1"
}

// PlatformName returns the platform of this profile without the client hint quoting
func (p BrowserProfile) PlatformName() string {
	return strings.Trim(p.SecChUaPlatform, `"`)
}

// Brands returns the navigator.userAgentData brands matching the Sec-CH-UA header
func (p BrowserProfile) Brands() []BrowserBrand {
	matches := reBrowserBrand.FindAllStringSubmatch(p.SecChUa, -1)
	brands := make([]BrowserBrand, 0, len(matches))
	for _, match := range matches {
		brands = append(brands, BrowserBrand{Brand: match[1], Version: match[2]})
	}

	return brands
}

// Plugins returns the navigator.plugins list of this profile, mobile has no PDF viewer
func (p BrowserProfile) Plugins() []BrowserPlugin {
	if p.IsMobile() {
		return nil
	}

	return chromePlugins
}

// MaxTouchPoints returns the touch point count this profile reports
func (p BrowserProfile) MaxTouchPoints() int {
	if p.IsMobile() {
		return 5
	}

	return 0
}

// Orientation returns the screen orientation this profile reports
func (p BrowserProfile) Orientation() string {
	if p.IsMobile() {
		return "portrait-primary"
	}

	return "landscape-primary"
}

// browserProfiles represents a pool of realistic browser profiles
var browserProfiles = []BrowserProfile{
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
}

// RandomBrowserProfile returns a random browser identity profile
func RandomBrowserProfile() BrowserProfile {
	return browserProfiles[rand.Intn(len(browserProfiles))]
}
