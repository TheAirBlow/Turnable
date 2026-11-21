package vk

import (
	"bytes"
	"math"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	captchaBlockedPermission = "denied"                                                          // permission state a cross-origin frame reports
	captchaOracleEvalLen     = 326                                                               // String(eval).length on the captcha page, which wraps eval
	captchaOracleErrorProps  = "length,name,prototype,captureStackTrace,isError,stackTraceLimit" // Object.getOwnPropertyNames(Error)
)

// captchaBasicProbes lists the probes the page script runs first, in its default order
var captchaBasicProbes = []string{
	"globals", "ua", "frame", "match_media", "plugins", "nav_tamper", "referrer", "css", "native_integrity",
	"cookie_test", "ancestor_origins", "sandbox_behavior", "max_touch_points", "timezone_locale",
	"device_pixel_ratio", "env_ua", "env_viewport", "chrome_runtime", "shadow_dom_check", "ua_high_entropy",
	"origin_via_self", "media_codecs",
}

// captchaPluginNames lists the built-in PDF viewers every desktop Chrome reports
var captchaPluginNames = []string{"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"}

// captchaGLExtensions lists the WebGL extensions ANGLE exposes
var captchaGLExtensions = []string{
	"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control", "EXT_color_buffer_half_float", "EXT_depth_clamp",
	"EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth", "EXT_polygon_offset_clamp", "EXT_sRGB",
	"EXT_shader_texture_lod", "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc",
	"EXT_texture_filter_anisotropic", "EXT_texture_mirror_clamp_to_edge", "KHR_parallel_shader_compile",
	"OES_element_index_uint", "OES_fbo_render_mipmap", "OES_standard_derivatives", "OES_texture_float",
	"OES_texture_float_linear", "OES_texture_half_float", "OES_texture_half_float_linear",
	"OES_vertex_array_object", "WEBGL_blend_func_extended", "WEBGL_color_buffer_float",
	"WEBGL_compressed_texture_s3tc", "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
	"WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers", "WEBGL_lose_context", "WEBGL_multi_draw",
	"WEBGL_polygon_mode",
}

// captchaFontProbes lists the fonts the page checks for
var captchaFontProbes = []string{"Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Trebuchet MS", "Tahoma", "Segoe UI", "Consolas", "Roboto"}

// captchaFields is the result object of a single probe
type captchaFields = map[string]any

// captchaProbe is the outcome of a single telemetry probe
type captchaProbe struct {
	OK         bool    `json:"ok"`          // Probe completed without error
	Result     any     `json:"result"`      // Probe result
	DurationMs float64 `json:"duration_ms"` // Time the probe took in milliseconds
}

// captchaTelemetry keeps probes in the order the page script ran them
type captchaTelemetry struct {
	names  []string       // probe names
	probes []captchaProbe // probe outcomes, parallel to names
}

// MarshalJSON encodes the probes as an object that preserves their order
func (t captchaTelemetry) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	for i, name := range t.names {
		if i > 0 {
			buf.WriteByte(',')
		}

		key, err := marshalCaptchaJSON(name)
		if err != nil {
			return nil, err
		}

		value, err := marshalCaptchaJSON(t.probes[i])
		if err != nil {
			return nil, err
		}

		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// captchaRun simulates one run of the page's telemetry script on the profile's device
type captchaRun struct {
	profile   common.BrowserProfile
	page      *captchaPage
	started   time.Time        // navigation start of the captcha page
	now       float64          // milliseconds since navigation start
	origin    float64          // monotonic clock reading at navigation start, in milliseconds
	slow      float64          // how much slower than an average desktop the device runs
	telemetry captchaTelemetry // probes recorded so far
}

// runCaptchaTelemetry plays the telemetry script and returns its probes and the time it took
func runCaptchaTelemetry(profile common.BrowserProfile, page *captchaPage, started time.Time, startOffset float64) (captchaTelemetry, float64) {
	run := &captchaRun{
		profile: profile,
		page:    page,
		started: started,
		now:     startOffset,
		origin:  float64(3_000_000+rand.Intn(400_000_000)) + rand.Float64(),
		slow:    1 / profile.CPUSpeed,
	}

	for _, name := range captchaProbeOrder(page.ProbeOrder) {
		run.basicProbe(name)
	}

	run.notifPermissions()
	run.webgl()
	run.audio()
	run.reflowTiming()
	run.domChain()
	run.wasm()
	run.subpixelFont()
	run.timingBaseline()
	run.canvas()
	run.fontEnumeration()
	run.visibilityRAF()
	run.mediaDevices()
	run.speechVoices()
	run.workerRealm()
	run.timerResolution()
	run.gpuRenderTiming()
	run.jsEngineOracle()
	run.pristineRealm()
	run.pageLifecycle()
	run.clockSnapshot()
	run.viewportGeometry()

	return run.telemetry, run.now - startOffset
}

// captchaProbeOrder merges the order the server sent with the page's defaults the way the script does
func captchaProbeOrder(sent []string) []string {
	order := make([]string, 0, len(captchaBasicProbes))
	for _, name := range sent {
		if slices.Contains(captchaBasicProbes, name) && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}

	for _, name := range captchaBasicProbes {
		if !slices.Contains(order, name) {
			order = append(order, name)
		}
	}

	return order
}

// record stores a finished probe and advances the clock past it
func (r *captchaRun) record(name string, ms float64, result any) {
	r.telemetry.names = append(r.telemetry.names, name)
	r.telemetry.probes = append(r.telemetry.probes, captchaProbe{OK: true, Result: result, DurationMs: round1(ms)})
	r.now += ms + 0.1 + rand.Float64()*0.4
}

// spend returns a random probe duration in milliseconds scaled to the device speed
func (r *captchaRun) spend(minMs, maxMs float64) float64 {
	return round1((minMs + rand.Float64()*(maxMs-minMs)) * r.slow)
}

// perfNow reads performance.now() at the given time, quantized to its 100µs resolution
func (r *captchaRun) perfNow(ms float64) float64 {
	return math.Floor((r.origin+ms)*10)/10 - r.origin
}

// basicProbe records one of the fast probes that run before the heavy ones
func (r *captchaRun) basicProbe(name string) {
	p := r.profile

	switch name {
	case "globals":
		r.record(name, r.spend(6, 14), captchaFields{
			"doc": true, "win": true, "nav": true, "webdriver": false, "subtle": true, "secure": true,
			"gcs": true, "raf": true, "wasm": true, "plugins_len": len(captchaPluginNames),
			"languages_len": len(p.Languages), "chromePresent": true, "hw": p.HardwareConcurrency, "mem": p.DeviceMemory,
		})
	case "ua":
		r.record(name, r.spend(0.1, 0.4), captchaFields{
			"userAgent": p.UserAgent,
			"userAgentData": captchaFields{
				"brands": p.Brands, "platform": p.OS, "mobile": p.IsMobile(), "architecture": nil,
			},
		})
	case "frame":
		r.record(name, r.spend(0.1, 0.3), captchaFields{
			"frameElement": nil, "ancestorOriginsLen": 0, "ancestorOriginsSupported": false, "parentAccessible": false,
		})
	case "match_media":
		r.record(name, r.spend(0.1, 0.4), captchaFields{
			"prefersDark": p.PrefersDark, "prefersLight": !p.PrefersDark, "reducedMotion": false,
			"pointerFine": !p.IsMobile(), "colorSchemeSupported": true,
		})
	case "plugins":
		mimeTypes := make([][]string, len(captchaPluginNames))
		descriptions := make([]string, len(captchaPluginNames))
		for i := range captchaPluginNames {
			mimeTypes[i] = []string{}
			descriptions[i] = "Portable Document Format"
		}

		r.record(name, r.spend(0.5, 1.3), captchaFields{
			"length": len(captchaPluginNames), "names": captchaPluginNames, "descriptions": descriptions,
			"mimeTypes": mimeTypes, "isChrome": true, "pdfViewerEnabled": true, "pluginArrayNative": true,
		})
	case "nav_tamper":
		r.record(name, r.spend(0.2, 0.5), captchaFields{
			"tampered": false, "el_ctor": "HTMLDivElement", "style_ctor": "CSSStyleDeclaration",
			"nav_ctor": "Navigator", "alert_native": true, "to_string_native": true,
		})
	case "referrer":
		r.record(name, r.spend(0.1, 0.3), captchaFields{
			"referrer": captchaParentOrigin + "/", "inIframe": true, "domain": strings.TrimPrefix(captchaPageOrigin, "https://"),
		})
	case "css":
		r.record(name, r.spend(0.2, 0.5), captchaFields{
			"expectedMissing": 0, "engine_floor": 123, "supported_per_tier": []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		})
	case "native_integrity":
		// The page wraps addEventListener itself, so a genuine browser reports it as non-native.
		r.record(name, r.spend(0.2, 0.5), captchaFields{
			"protoMatch": true, "xhrNative": true, "xhrSendNative": true, "addEventListenerNative": false,
			"alertNative": true, "toStringNative": true,
		})
	case "cookie_test":
		r.record(name, r.spend(0.8, 2.2), captchaFields{"write": true})
	case "ancestor_origins":
		r.record(name, r.spend(0.1, 0.2), captchaFields{"ancestorOrigin": nil})
	case "sandbox_behavior":
		r.record(name, r.spend(0.3, 0.8), captchaFields{"originIsNull": false, "localStorage": true, "sessionStorage": true})
	case "max_touch_points":
		r.record(name, r.spend(0.2, 0.4), captchaFields{"maxTouchPoints": 0})
	case "timezone_locale":
		r.record(name, r.spend(0.1, 0.4), captchaFields{"timezone": p.Timezone, "languages": p.Languages, "tz_offset": p.TZOffset})
	case "device_pixel_ratio":
		r.record(name, r.spend(0, 0.2), captchaFields{"dpr": p.PixelRatio, "orientation": "landscape-primary", "orientationAngle": 0})
	case "env_ua":
		r.record(name, r.spend(0.2, 0.5), captchaFields{
			"app_version": strings.TrimPrefix(p.UserAgent, "Mozilla/"), "oscpu": nil, "platform": p.NavPlatform,
			"ua_zero_tail": true, "brands_ua_sync": true, "js_heap_gb": p.JSHeapGB,
		})
	case "env_viewport":
		r.record(name, r.spend(0.1, 0.4), captchaFields{
			"avail_ok": true, "vv_width": p.InnerWidth, "inner_width": p.InnerWidth, "vv_scale": 1, "dpr_media_ok": true,
		})
	case "chrome_runtime":
		r.record(name, r.spend(0.1, 0.2), captchaFields{"present": false})
	case "shadow_dom_check":
		r.record(name, r.spend(0.1, 0.3), captchaFields{"customElements": true, "shadowDom": true})
	case "ua_high_entropy":
		// A cross-origin frame without a permissions policy only gets the low-entropy hints.
		r.record(name, r.spend(8, 20), captchaFields{
			"platform": p.OS, "platformVersion": nil, "architecture": nil, "model": nil, "uaFullVersion": nil,
			"fullVersionList": []string{}, "bitness": nil, "formFactors": []string{}, "wow64": false,
		})
	case "origin_via_self":
		r.record(name, r.spend(0.1, 0.3), captchaFields{"origin": captchaPageOrigin, "originIsNull": false})
	case "media_codecs":
		r.record(name, r.spend(0.3, 0.9), captchaMediaCodecs(p))
	}
}

// captchaMediaCodecs reports canPlayType and MediaSource support, which depend on the codecs the build ships
func captchaMediaCodecs(p common.BrowserProfile) captchaFields {
	if p.Chromium {
		return captchaFields{
			"h264": 0, "avc_high": 0, "hvc": 0, "vp9": 2, "vp8": 2, "theora": 0, "mp4a": 0, "aac": 0, "m4a": 0, "mp3": 2,
			"mse_h264": 0, "mse_vp9": 1,
		}
	}

	hevc := 0
	if p.OS != "Linux" {
		hevc = 2
	}

	return captchaFields{
		"h264": 2, "avc_high": 2, "hvc": hevc, "vp9": 2, "vp8": 2, "theora": 0, "mp4a": 2, "aac": 2, "m4a": 1, "mp3": 2,
		"mse_h264": 1, "mse_vp9": 1,
	}
}

// notifPermissions records the permission states a cross-origin frame reports
func (r *captchaRun) notifPermissions() {
	r.record("notif_permissions", r.spend(40, 90), captchaFields{
		"notif": nil, "notifications_q": captchaBlockedPermission, "agree": nil, "geolocation": captchaBlockedPermission,
		"camera": captchaBlockedPermission, "microphone": captchaBlockedPermission, "midi": captchaBlockedPermission,
	})
}

// webgl records the WebGL identity of the graphics adapter
func (r *captchaRun) webgl() {
	gpu := r.profile.GPU
	r.record("webgl", r.spend(15, 45), captchaFields{
		"vendor": gpu.Vendor, "renderer": gpu.Renderer, "available": true,
		"glsl_version": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)", "max_texture_size": 16384,
		"extensions": captchaGLExtensions, "hw_accel": true, "timedOut": false,
	})
}

// audio records the audio fingerprint
func (r *captchaRun) audio() {
	r.record("audio_sig", r.spend(4, 14), captchaFields{"hash": r.profile.AudioHash})
}

// reflowTiming records the layout timings of three padded boxes
func (r *captchaRun) reflowTiming() {
	timings := make([]captchaFields, 3)
	for i, size := range [][3]int{{100, 0, 0}, {216, 16, 0}, {332, 32, 0}} {
		timings[i] = captchaFields{"w": size[0], "h": size[1], "ms": []float64{0, 0, 0.1, 0.1, 0.2}[rand.Intn(5)]}
	}

	r.record("reflow_timing", r.spend(0.8, 2), captchaFields{"timings": timings, "timedOut": false})
}

// domChain records the hash of four resized boxes, whose height is always zero
func (r *captchaRun) domChain() {
	var hash int32
	for i := int32(0); i < 4; i++ {
		hash = (hash ^ (100+i*20)<<4) * 31
	}

	r.record("dom_chain", r.spend(3, 6), captchaFields{"hash": hash, "iterations": 4})
}

// wasm records how fast a tiny module compiles and runs
func (r *captchaRun) wasm() {
	r.record("wasm", r.spend(1.2, 3), captchaFields{
		"compileMs": round3((0.5 + rand.Float64()*1.5) * r.slow), "execMs": round3((0.2 + rand.Float64()*0.8) * r.slow), "supported": true,
	})
}

// subpixelFont records the width of a text sample in the three generic font families
func (r *captchaRun) subpixelFont() {
	widths := map[string][3]captchaFields{
		"Windows": {{"font": "serif", "width": 46.796875, "height": 13}, {"font": "sans-serif", "width": 44.828125, "height": 13}, {"font": "monospace", "width": 57.890625, "height": 15}},
		"macOS":   {{"font": "serif", "width": 46.828125, "height": 13}, {"font": "sans-serif", "width": 44.8125, "height": 13}, {"font": "monospace", "width": 63.1875, "height": 14}},
		"Linux":   {{"font": "serif", "width": 46.765625, "height": 13}, {"font": "sans-serif", "width": 44.796875, "height": 13}, {"font": "monospace", "width": 63.125, "height": 16}},
	}[r.profile.OS]

	r.record("subpixel_font", r.spend(12, 30), captchaFields{"widths": widths, "timedOut": false})
}

// timingBaseline records CPU loop timings and consecutive timer reads
func (r *captchaRun) timingBaseline() {
	cpu := make([]float64, 3)
	for i := range cpu {
		cpu[i] = round1((0.2 + rand.Float64()*0.3) * r.slow)
	}

	start := r.now + 8 + rand.Float64()*6
	res := make([]float64, 5)
	for i := range res {
		res[i] = r.perfNow(start + float64(i)*(4.05+rand.Float64()*0.15))
	}

	r.record("timing_baseline", r.spend(60, 95), captchaFields{"cpu": cpu, "res": res, "timedOut": false})
}

// canvas records the canvas fingerprint
func (r *captchaRun) canvas() {
	r.record("canvas_fingerprint", r.spend(20, 60), captchaFields{"hash": r.profile.CanvasHash, "timedOut": false})
}

// fontEnumeration records installed fonts until the probe gives up after 100ms
func (r *captchaRun) fontEnumeration() {
	fonts := []string{}
	elapsed := 2.0
	timedOut := false

	for _, font := range captchaFontProbes {
		if elapsed > 100 {
			timedOut = true
			break
		}

		if slices.Contains(r.profile.Fonts, font) {
			fonts = append(fonts, font)
			elapsed += (7 + rand.Float64()*5) * r.slow
		} else {
			elapsed += 4.3 + rand.Float64()*1.2
		}
	}

	r.record("font_enumeration", elapsed, captchaFields{"fonts": fonts, "timedOut": timedOut})
}

// visibilityRAF records the animation frames delivered during a 300ms window
func (r *captchaRun) visibilityRAF() {
	duration := round1(300 + rand.Float64()*1000/float64(r.profile.RefreshRate))
	frames := int(math.Round(duration * float64(r.profile.RefreshRate) / 1000))

	r.record("visibility_raf", duration+0.2, captchaFields{
		"visibilityState": "visible", "startVisibilityState": "visible", "documentHidden": false, "documentPrerendering": false,
		"anyRafFrameDelivered": true, "frames": frames, "fps": int(math.Round(float64(frames) * 1000 / duration)),
		"durationMs": duration, "hiddenMs": 0,
	})
}

// mediaDevices records the device counts, which stay anonymous without a permission
func (r *captchaRun) mediaDevices() {
	r.record("media_devices", r.spend(20, 70), captchaFields{
		"avail": true, "audio_in": 1, "video_in": r.profile.MediaInputs, "audio_out": 1, "has_ids": false, "has_labels": false,
	})
}

// speechVoices records the speech synthesis voices of the operating system
func (r *captchaRun) speechVoices() {
	p := r.profile
	if p.OS == "Linux" {
		r.record("speech_voices", r.spend(0.2, 0.6), captchaFields{"avail": false})
		return
	}

	local, remote, langs, defaultLang := 4+rand.Intn(2), 15+rand.Intn(3), 13+rand.Intn(7), "en-US"
	if p.OS == "macOS" {
		local, remote, langs = 70+rand.Intn(110), 15+rand.Intn(2), 25+rand.Intn(16)
	} else if strings.HasPrefix(p.Languages[0], "ru") {
		defaultLang = "ru-RU"
	}

	locale := p.Languages[0]
	waited := 30 + rand.Intn(220)

	r.record("speech_voices", float64(waited)+0.3, captchaFields{
		"avail": true, "count": local + remote, "local": local, "langs": langs, "default_lang": defaultLang,
		"locale": locale, "lang_mismatch": strings.Split(defaultLang, "-")[0] != strings.Split(locale, "-")[0],
		"settled": true, "waited_ms": waited,
	})
}

// workerRealm records how a dedicated worker sees the navigator
func (r *captchaRun) workerRealm() {
	hw := r.profile.HardwareConcurrency
	r.record("worker_realm", r.spend(3, 10), captchaFields{
		"ok": true, "ua_diff": false, "platform_diff": false, "webdriver_worker": nil, "webdriver_diff": true,
		"hw": hw, "hw_worker": hw, "hw_diff": false,
	})
}

// timerResolution records how finely performance.now() ticks
func (r *captchaRun) timerResolution() {
	reads := 256 * int(float64(90_000+rand.Intn(50_000))/256*r.profile.CPUSpeed)
	span := []float64{20, 20, 20.1}[rand.Intn(3)]
	changes := int(math.Round(span * 10))
	tick := r.perfNow(r.now+0.1) - r.perfNow(r.now)

	r.record("timer_resolution", span+0.3, captchaFields{
		"ok": true, "perf_min": tick, "perf_zero": reads - changes, "perf_reads": reads, "span": span,
		"changes": changes, "origin_delta": round3(rand.Float64()),
	})
}

// gpuRenderTiming records how many frames the adapter draws in 150ms
func (r *captchaRun) gpuRenderTiming() {
	gpu := r.profile.GPU
	window := r.perfNow(r.now+150+rand.Float64()*0.9) - r.perfNow(r.now)
	firstFrame := r.perfNow(r.now+0.5+rand.Float64()*2) - r.perfNow(r.now)

	r.record("gpu_render_timing", window+8+rand.Float64()*6, captchaFields{
		"ok": true, "frames": gpu.Frames[0] + rand.Intn(gpu.Frames[1]-gpu.Frames[0]+1), "cap": 2000,
		"window_ms": window, "first_frame_ms": firstFrame, "renderer": gpu.Renderer, "gl_error": 0,
	})
}

// jsEngineOracle records V8 specifics, including where the stack trace probe sits in the page
func (r *captchaRun) jsEngineOracle() {
	stackAt := "    at " + r.page.URL + ":" + strconv.Itoa(r.page.OracleLine) + ":" + strconv.Itoa(r.page.OracleColumn)

	r.record("js_engine_oracle", r.spend(0.3, 0.6), captchaFields{
		"ok": true, "eval_native_len": captchaOracleEvalLen, "fpt_native_len": 37, "stack_head": "Error: oracle",
		"stack_at": stackAt, "err_props": captchaOracleErrorProps,
		"tofixed_msg": "toFixed() digits argument must be between 0 and 100",
	})
}

// pristineRealm records how builtins look in a fresh iframe compared with the page itself
func (r *captchaRun) pristineRealm() {
	accessor, method := "ag-:undefined:e1:c1|n", "d--:f:e1:c1|n"
	items := []captchaFields{}
	for _, item := range [][2]string{
		{"Navigator.prototype.userAgent", accessor}, {"Navigator.prototype.webdriver", accessor},
		{"Navigator.prototype.hardwareConcurrency", accessor}, {"Navigator.prototype.deviceMemory", accessor},
		{"Navigator.prototype.languages", accessor}, {"Navigator.prototype.plugins", accessor},
		{"Screen.prototype.width", accessor}, {"Function.prototype.toString", "d--:f:e0:c1|n"},
		{"HTMLCanvasElement.prototype.toDataURL", method}, {"CanvasRenderingContext2D.prototype.getImageData", method},
		{"AudioBuffer.prototype.getChannelData", method}, {"Performance.prototype.now", method},
		{"WebGLRenderingContext.prototype.getParameter", method},
	} {
		items = append(items, captchaFields{"p": item[0], "m": item[1], "r": item[1]})
	}

	r.record("pristine_realm", r.spend(20, 45), captchaFields{"ok": true, "items": items, "readable": len(items)})
}

// pageLifecycle records how the page was opened
func (r *captchaRun) pageLifecycle() {
	r.record("page_lifecycle_provenance", r.spend(0.2, 0.5), captchaFields{
		"navtype": "navigate", "hist": r.profile.HistoryDepth, "ready": "complete", "now_ms": int(math.Round(r.now)),
		"reload_count": 0, "reload_span_ms": nil,
	})
}

// clockSnapshot records the wall clock next to the page's time origin
func (r *captchaRun) clockSnapshot() {
	origin := r.started.UnixMilli()
	r.record("client_clock_snapshot", r.spend(0.1, 0.3), captchaFields{
		"now_ms": origin + int64(math.Round(r.now)), "perf_origin": origin,
	})
}

// viewportGeometry records the window and screen rectangles
func (r *captchaRun) viewportGeometry() {
	p := r.profile
	r.record("viewport_frame_geometry", r.spend(0.1, 0.3), captchaFields{
		"outer_w": p.OuterWidth, "outer_h": p.OuterHeight, "inner_w": p.InnerWidth, "inner_h": p.InnerHeight,
		"screen_w": p.ScreenWidth, "screen_h": p.ScreenHeight, "avail_w": p.AvailWidth, "avail_h": p.AvailHeight,
		"screen_x": 0, "screen_y": 0, "fullscreen": false, "in_iframe": true,
	})
}

// round1 rounds to a tenth of a millisecond
func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

// round3 rounds to a microsecond
func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}
