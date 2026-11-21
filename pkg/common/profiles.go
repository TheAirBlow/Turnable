package common

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// chromeLatestMajor is the newest Chrome major version the profile pool imitates
const chromeLatestMajor = 157

// Canvas and audio fingerprints of the latest Chromium, which most users share
const (
	chromiumCanvasHash = "8cd7bffe8ab8140ed1b70a70e24805e1d747a4ea90ba79035a0b01ebda3374d0"
	chromiumAudioHash  = "ed6bfa566a9fed02b8a92c1b1c8e2c65299d2567c710e1f236b2361b05de51f3"
)

// BrowserProfile describes one consistent desktop Chromium device
type BrowserProfile struct {
	UserAgent       string // User-Agent header
	SecChUa         string // Sec-CH-UA header
	SecChUaMobile   string // Sec-CH-UA-Mobile header
	SecChUaPlatform string // Sec-CH-UA-Platform header
	AcceptLanguage  string // Accept-Language header

	ChromeMajor  int            // Chrome major version
	Chromium     bool           // unbranded Chromium build without proprietary codecs
	Brands       []BrowserBrand // navigator.userAgentData.brands
	OS           string         // navigator.userAgentData.platform
	NavPlatform  string         // navigator.platform
	Languages    []string       // navigator.languages
	Timezone     string         // IANA timezone
	TZOffset     int            // Date.getTimezoneOffset in minutes
	PrefersDark  bool           // prefers-color-scheme: dark
	RefreshRate  int            // display refresh rate in Hz
	CPUSpeed     float64        // relative CPU speed, 1 is an average desktop
	MediaInputs  int            // number of video inputs reported by enumerateDevices
	HistoryDepth int            // history.length of the tab the captcha opens in

	ScreenWidth  int     // screen.width
	ScreenHeight int     // screen.height
	AvailWidth   int     // screen.availWidth
	AvailHeight  int     // screen.availHeight
	OuterWidth   int     // window.outerWidth
	OuterHeight  int     // window.outerHeight
	InnerWidth   int     // window.innerWidth
	InnerHeight  int     // window.innerHeight
	PixelRatio   float64 // window.devicePixelRatio

	HardwareConcurrency int        // navigator.hardwareConcurrency
	DeviceMemory        int        // navigator.deviceMemory in GB
	GPU                 BrowserGPU // WebGL renderer
	Fonts               []string   // detectable fonts out of the probe list
	JSHeapGB            float64    // performance.memory.jsHeapSizeLimit in GB
	CanvasHash          string     // canvas fingerprint hash
	AudioHash           string     // audio fingerprint hash
	FingerprintID       string     // stable browser fingerprint ID
}

// BrowserBrand holds a single navigator.userAgentData brand entry
type BrowserBrand struct {
	Brand   string `json:"brand"`   // Brand name
	Version string `json:"version"` // Major version
}

// BrowserGPU holds the WebGL identity of a graphics adapter
type BrowserGPU struct {
	Vendor   string // unmasked vendor
	Renderer string // unmasked renderer
	Frames   [2]int // range of frames drawn in a 150ms render benchmark
}

// browserScreen is a screen size in CSS pixels with its pixel ratio
type browserScreen struct {
	Width, Height int
	PixelRatio    float64
}

// browserPlatform holds what is shared by every device of one operating system
type browserPlatform struct {
	OS          string          // client hint platform
	UAToken     string          // platform part of the user agent
	NavPlatform string          // navigator.platform
	Weight      int             // relative share in the pool
	Screens     []browserScreen // common screen sizes
	Insets      []int           // screen height taken by the taskbar, menu bar or panel
	ChromeUI    []int           // height of the browser toolbars
	Cores       []int           // hardware concurrency choices
	GPUs        []BrowserGPU    // graphics adapters
	Fonts       [][]string      // detectable font sets
}

var browserPlatforms = []browserPlatform{
	{
		OS:          "Windows",
		UAToken:     "Windows NT 10.0; Win64; x64",
		NavPlatform: "Win32",
		Weight:      70,
		Screens: []browserScreen{
			{1920, 1080, 1}, {1920, 1080, 1}, {1920, 1080, 1}, {1536, 864, 1.25}, {1536, 864, 1.25},
			{1366, 768, 1}, {2560, 1440, 1}, {1600, 900, 1}, {1440, 900, 1}, {1280, 720, 1.5},
			{2048, 1152, 1.25}, {1920, 1200, 1},
		},
		Insets:   []int{40, 48, 48},
		ChromeUI: []int{79, 87, 87, 111, 119},
		Cores:    []int{4, 6, 8, 8, 12, 12, 16, 16, 20, 24},
		GPUs: []BrowserGPU{
			{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{900, 1600}},
			{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 (0x00002882) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{1100, 1900}},
			{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00001F82) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{600, 1100}},
			{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB (0x00001C03) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{550, 1000}},
			{"Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{150, 320}},
			{"Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E92) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{180, 360}},
			{"Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{260, 520}},
			{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{900, 1600}},
			{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics (0x00001638) Direct3D11 vs_5_0 ps_5_0, D3D11)", [2]int{220, 450}},
		},
		Fonts: [][]string{
			{"Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Trebuchet MS", "Tahoma", "Segoe UI", "Consolas"},
		},
	},
	{
		OS:          "macOS",
		UAToken:     "Macintosh; Intel Mac OS X 10_15_7",
		NavPlatform: "MacIntel",
		Weight:      12,
		Screens: []browserScreen{
			{1440, 900, 2}, {1512, 982, 2}, {1512, 982, 2}, {1728, 1117, 2}, {1470, 956, 2},
			{1680, 1050, 2}, {1920, 1080, 1}, {2560, 1440, 1},
		},
		Insets:   []int{25, 37, 38},
		ChromeUI: []int{79, 87, 87, 112},
		Cores:    []int{8, 8, 10, 12},
		GPUs: []BrowserGPU{
			{"Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)", [2]int{500, 900}},
			{"Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)", [2]int{600, 1100}},
			{"Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M3, Unspecified Version)", [2]int{700, 1300}},
			{"Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro, Unspecified Version)", [2]int{800, 1400}},
		},
		Fonts: [][]string{
			{"Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Trebuchet MS", "Tahoma"},
		},
	},
	{
		OS:          "Linux",
		UAToken:     "X11; Linux x86_64",
		NavPlatform: "Linux x86_64",
		Weight:      18,
		Screens: []browserScreen{
			{1920, 1080, 1}, {1920, 1080, 1}, {2560, 1440, 1}, {1366, 768, 1}, {1920, 1200, 1},
		},
		Insets:   []int{0, 27, 32, 44},
		ChromeUI: []int{79, 87, 87, 111},
		Cores:    []int{4, 8, 8, 12, 16, 16, 24},
		GPUs: []BrowserGPU{
			{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon 660M (radeonsi rembrandt ACO), OpenGL 4.6)", [2]int{230, 330}},
			{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT (radeonsi navi22 ACO), OpenGL 4.6)", [2]int{900, 1600}},
			{"Google Inc. (Intel)", "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)", [2]int{150, 300}},
			{"Google Inc. (Intel)", "ANGLE (Intel, Mesa Intel(R) Xe Graphics (TGL GT2), OpenGL 4.6)", [2]int{250, 480}},
			{"Google Inc. (NVIDIA Corporation)", "ANGLE (NVIDIA Corporation, NVIDIA GeForce GTX 1660 SUPER/PCIe/SSE2, OpenGL 4.5.0)", [2]int{650, 1150}},
		},
		Fonts: [][]string{
			{"Arial", "Verdana", "Times New Roman", "Georgia", "Trebuchet MS", "Tahoma", "Segoe UI", "Consolas"},
			{"Arial", "Verdana", "Times New Roman", "Georgia", "Trebuchet MS", "Tahoma"},
		},
	},
}

// browserLocale is a navigator.languages list with its Accept-Language header
type browserLocale struct {
	Languages      []string
	AcceptLanguage string
}

var browserLocales = []browserLocale{
	{[]string{"ru-RU", "ru", "en-US", "en"}, "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
	{[]string{"ru-RU", "ru", "en-US", "en"}, "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
	{[]string{"ru", "en-US", "en"}, "ru,en-US;q=0.9,en;q=0.8"},
	{[]string{"en-US", "en"}, "en-US,en;q=0.9"},
	{[]string{"en-US", "en", "ru"}, "en-US,en;q=0.9,ru;q=0.8"},
}

// browserTimezone is an IANA timezone with its fixed UTC offset in minutes
type browserTimezone struct {
	Name   string
	Offset int
}

// browserTimezones lists Russian timezones, none of which observe DST
var browserTimezones = []browserTimezone{
	{"Europe/Moscow", -180}, {"Europe/Moscow", -180}, {"Europe/Moscow", -180}, {"Europe/Moscow", -180},
	{"Europe/Kaliningrad", -120}, {"Europe/Samara", -240}, {"Asia/Yekaterinburg", -300},
	{"Asia/Omsk", -360}, {"Asia/Novosibirsk", -420}, {"Asia/Krasnoyarsk", -420},
	{"Asia/Irkutsk", -480}, {"Asia/Vladivostok", -600},
}

// IsMobile reports whether this profile describes a mobile browser
func (p BrowserProfile) IsMobile() bool {
	return p.SecChUaMobile == "?1"
}

// RandomBrowserProfile generates a random but internally consistent desktop Chromium profile
func RandomBrowserProfile() BrowserProfile {
	platform := pickWeightedPlatform()
	locale := browserLocales[rand.Intn(len(browserLocales))]
	timezone := browserTimezones[rand.Intn(len(browserTimezones))]
	screen := platform.Screens[rand.Intn(len(platform.Screens))]

	major := chromeLatestMajor - []int{0, 0, 0, 1, 1, 2}[rand.Intn(6)]
	chromium := platform.OS == "Linux" && rand.Intn(3) == 0
	brands := chromeBrands(major, chromium)

	availHeight := screen.Height - platform.Insets[rand.Intn(len(platform.Insets))]
	innerHeight := availHeight - platform.ChromeUI[rand.Intn(len(platform.ChromeUI))]

	cores := platform.Cores[rand.Intn(len(platform.Cores))]
	memory := []int{8, 16, 16, 32}[rand.Intn(4)]
	if cores <= 4 {
		memory = []int{4, 8}[rand.Intn(2)]
	}

	refreshRate := []int{60, 60, 60, 60, 60, 75, 120, 144, 165}[rand.Intn(9)]
	if platform.OS == "macOS" {
		refreshRate = []int{60, 120}[rand.Intn(2)]
	}

	gpu := platform.GPUs[rand.Intn(len(platform.GPUs))]
	fingerprint := randomHex(16)

	return BrowserProfile{
		UserAgent:       fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", platform.UAToken, major),
		SecChUa:         formatSecChUa(brands),
		SecChUaMobile:   "?0",
		SecChUaPlatform: strconv.Quote(platform.OS),
		AcceptLanguage:  locale.AcceptLanguage,

		ChromeMajor:  major,
		Chromium:     chromium,
		Brands:       brands,
		OS:           platform.OS,
		NavPlatform:  platform.NavPlatform,
		Languages:    locale.Languages,
		Timezone:     timezone.Name,
		TZOffset:     timezone.Offset,
		PrefersDark:  rand.Intn(100) < 35,
		RefreshRate:  refreshRate,
		CPUSpeed:     0.6 + rand.Float64()*0.9,
		MediaInputs:  rand.Intn(2),
		HistoryDepth: 1 + rand.Intn(6),

		ScreenWidth:  screen.Width,
		ScreenHeight: screen.Height,
		AvailWidth:   screen.Width,
		AvailHeight:  availHeight,
		OuterWidth:   screen.Width,
		OuterHeight:  availHeight,
		InnerWidth:   screen.Width,
		InnerHeight:  innerHeight,
		PixelRatio:   screen.PixelRatio,

		HardwareConcurrency: cores,
		DeviceMemory:        memory,
		GPU:                 gpu,
		Fonts:               platform.Fonts[rand.Intn(len(platform.Fonts))],
		JSHeapGB:            jsHeapLimit(memory),
		CanvasHash:          chromiumCanvasHash,
		AudioHash:           chromiumAudioHash,
		FingerprintID:       fingerprint,
	}
}

// randomHex returns n random bytes as a hex string
func randomHex(n int) string {
	data := make([]byte, n)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}

// jsHeapLimit returns the V8 heap limit in GB, a quarter of the memory capped at 4GB
func jsHeapLimit(memoryGB int) float64 {
	if memoryGB >= 16 {
		return []float64{4, 4.05, 4.09}[rand.Intn(3)]
	}

	return float64(memoryGB) / 4
}

// pickWeightedPlatform picks a platform according to its share
func pickWeightedPlatform() browserPlatform {
	total := 0
	for _, platform := range browserPlatforms {
		total += platform.Weight
	}

	n := rand.Intn(total)
	for _, platform := range browserPlatforms {
		if n < platform.Weight {
			return platform
		}
		n -= platform.Weight
	}

	return browserPlatforms[0]
}

// chromeBrands reproduces Chromium's GREASE brand list, which is seeded by the major version
func chromeBrands(major int, chromium bool) []BrowserBrand {
	greaseChars := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions := []string{"8", "99", "24"}

	grease := BrowserBrand{
		Brand:   "Not" + greaseChars[major%len(greaseChars)] + "A" + greaseChars[(major+1)%len(greaseChars)] + "Brand",
		Version: greaseVersions[major%len(greaseVersions)],
	}
	version := strconv.Itoa(major)

	if chromium {
		orders := [][2]int{{0, 1}, {1, 0}}
		order := orders[major%len(orders)]
		brands := make([]BrowserBrand, 2)
		brands[order[0]] = grease
		brands[order[1]] = BrowserBrand{Brand: "Chromium", Version: version}
		return brands
	}

	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	order := orders[major%len(orders)]
	brands := make([]BrowserBrand, 3)
	brands[order[0]] = grease
	brands[order[1]] = BrowserBrand{Brand: "Chromium", Version: version}
	brands[order[2]] = BrowserBrand{Brand: "Google Chrome", Version: version}
	return brands
}

// formatSecChUa renders a brand list as a Sec-CH-UA header value
func formatSecChUa(brands []BrowserBrand) string {
	parts := make([]string, len(brands))
	for i, brand := range brands {
		parts[i] = fmt.Sprintf(`"%s";v="%s"`, brand.Brand, brand.Version)
	}

	return strings.Join(parts, ", ")
}
