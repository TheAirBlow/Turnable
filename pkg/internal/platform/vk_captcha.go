package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/common"
)

var (
	reCaptchaPowInput   = regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)             // Extracts PoW input from captcha HTML
	reCaptchaDifficulty = regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`)               // Extracts PoW difficulty from captcha HTML
	reCaptchaWindowInit = regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?})\s*;`)          // Extracts captcha settings bootstrap JSON
	reCaptchaScriptSrc  = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)  // Finds captcha JS bundle URL
	reCaptchaDebugInfo  = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`) // Extracts hardcoded debug_info constant from captcha JS
	reCaptchaVersion    = regexp.MustCompile(`vkid/([0-9.]*)/not_robot_captcha\.js`)         // Extracts version of the captcha script

	errCaptchaRateLimit = errors.New("captcha session rate limit reached") // Marks exhausted captcha sessions

	captchaAPIVersion    = "5.131"    // last known version of the captcha API
	captchaScriptVersion = "1.1.1321" // last known version of the captcha script
)

// captchaInit represents window.init JSON object with captcha initialization data
type captchaInit struct {
	Data captchaInitData `json:"data"`
}

// captchaInitData represents captcha init data
type captchaInitData struct {
	ShowCaptchaType string               `json:"show_captcha_type"`
	CaptchaSettings []captchaInitSetting `json:"captcha_settings"`
}

// captchaInitSetting represents an available captcha setting
type captchaInitSetting struct {
	Type     string `json:"type"`
	Settings string `json:"settings"`
}

// captchaPage stores captcha metadata extracted from the challenge page
type captchaPage struct {
	PowInput      string
	PowDifficulty int
	ScriptURL     string
	Init          *captchaInit
}

// captchaCheck stores the result of a captcha verification attempt
type captchaCheck struct {
	Status       string
	SuccessToken string
	ShowType     string
}

// sliderPuzzle stores one parsed slider captcha puzzle
type sliderPuzzle struct {
	Image    image.Image
	Size     int
	Swaps    []int
	Attempts int
}

// sliderGuess stores the scoring result for one slider candidate
type sliderGuess struct {
	Index         int
	Swaps         []int
	Score         int64
	ScoreRGB      int64
	ScoreLuma     int64
	ScoreText     float64
	ConsensusRank int
}

// solveCaptchaWithRetry resolves a captcha challenge until success, context cancel, or rate limit
func (V *VKHandler) solveCaptchaWithRetry(ctx context.Context, apiErr vkAPIError) (string, error) {
	for attempt := 1; ; attempt++ {
		successToken, err := V.solveCaptcha(ctx, apiErr)
		if err == nil {
			return successToken, nil
		}

		slog.Warn("captcha solve attempt failed", "attempt", attempt, "error", err)
		if errors.Is(err, errCaptchaRateLimit) {
			return "", err
		}

		backoffSteps := min(attempt, 10)
		timer := time.NewTimer(time.Duration(backoffSteps) * 500 * time.Millisecond)

		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

// solveCaptcha fetches the captcha page and solves one challenge session
func (V *VKHandler) solveCaptcha(ctx context.Context, apiErr vkAPIError) (string, error) {
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

	if page.PowInput == "" {
		return "", errors.New("failed to find PoW settings")
	}

	settings := ""
	for _, setting := range page.Init.Data.CaptchaSettings {
		if setting.Type == page.Init.Data.ShowCaptchaType {
			settings = setting.Settings
		}
	}

	if page.Init.Data.ShowCaptchaType == "slider" && settings == "" {
		return "", errors.New("failed to find slider captcha settings")
	}

	slog.Debug("vk captcha solving pow", "difficulty", page.PowDifficulty)
	hash := solveCaptchaPoW(page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("captcha pow failed")
	}
	slog.Debug("vk captcha pow solved")

	base := common.NewValues(
		"session_token", apiErr.SessionToken,
		"domain", "vk.com",
		"adFp", apiErr.AdFP,
		"access_token", "",
	)

	if _, err := V.captchaRequest(ctx, "captchaNotRobot.settings", base); err != nil {
		return "", fmt.Errorf("captcha settings failed: %w", err)
	}

	slog.Info("vk captcha settings received", "show_type", page.Init.Data.ShowCaptchaType)

	r := rand.New(rand.NewSource(rand.Int63()))
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	browserFP := hex.EncodeToString(b)

	if m := reCaptchaVersion.FindSubmatch([]byte(page.ScriptURL)); len(m) > 1 {
		if string(m[1]) != captchaScriptVersion {
			slog.Warn("vk captcha script version changed", "last_known", captchaScriptVersion, "latest", string(m[1]))
		}
	}

	debugInfo, err := V.fetchDebugInfo(ctx, page.ScriptURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch debug info: %w", err)
	}

	var token string

	switch page.Init.Data.ShowCaptchaType {
	case "slider":
		token, err = V.solveSliderCaptcha(ctx, apiErr.SessionToken, apiErr.AdFP, browserFP, hash, settings, debugInfo)
	case "checkbox":
		token, err = V.solveCheckboxCaptcha(ctx, apiErr.SessionToken, apiErr.AdFP, browserFP, hash, debugInfo)
	default:
		token, err = "", fmt.Errorf("unsupported captcha type: %s", page.Init.Data.ShowCaptchaType)
	}

	if err != nil {
		return "", err
	}

	_, _ = V.captchaRequest(ctx, "captchaNotRobot.endSession", base)
	return token, nil
}

// fetchDebugInfo fetches the captcha JS and extracts the hardcoded debug_info constant, with caching.
func (V *VKHandler) fetchDebugInfo(ctx context.Context, scriptURL string) (string, error) {
	body, err := V.postVKFormRaw(ctx, http.MethodGet, scriptURL, nil, map[string]string{
		"Accept":  "text/javascript,*/*",
		"Referer": "https://id.vk.com/",
	})
	if err != nil {
		return "", err
	}

	m := reCaptchaDebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", errors.New("match not found")
	}

	v := string(m[1])
	slog.Debug("captcha debug_info fetched", "url", scriptURL, "value", v)
	return v, nil
}

// fetchCaptchaHTML downloads the captcha HTML page from redirect URI
func (V *VKHandler) fetchCaptchaHTML(ctx context.Context, redirectURI string) (string, error) {
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

	match := reCaptchaWindowInit.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha init json not found")
	}

	var init captchaInit
	_ = json.Unmarshal([]byte(match[1]), &init)
	page.Init = &init

	match = reCaptchaScriptSrc.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha script url not found")
	}

	page.ScriptURL = match[1]

	if match := reCaptchaPowInput.FindStringSubmatch(html); len(match) >= 2 {
		page.PowInput = match[1]
	}

	if page.PowInput == "" {
		return page, nil
	}

	match = reCaptchaDifficulty.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha difficulty const not found")
	}

	difficulty, err := strconv.Atoi(match[1])
	if err != nil || difficulty <= 0 {
		return nil, fmt.Errorf("invalid captcha difficulty %q", match[1])
	}

	page.PowDifficulty = difficulty
	return page, nil
}

// captchaRequest performs captcha API requests
func (V *VKHandler) captchaRequest(ctx context.Context, method string, form *common.Values) (map[string]any, error) {
	return V.postVKForm(ctx, vkAPIEndpoint+"/"+method+"?v="+captchaAPIVersion, form, map[string]string{
		"Origin":   "https://id.vk.com",
		"Referer":  "https://id.vk.com/",
		"Priority": "u=1, i",
	})
}

// generateDeviceInfo generates a device info JSON string
func generateDeviceInfo() string {
	device := map[string]interface{}{
		"screenWidth":             1920,
		"screenHeight":            1080,
		"screenAvailWidth":        1920,
		"screenAvailHeight":       1036,
		"innerWidth":              1920,
		"innerHeight":             949,
		"devicePixelRatio":        1,
		"language":                "en-US",
		"languages":               []string{"en-US"},
		"webdriver":               false,
		"hardwareConcurrency":     12,
		"deviceMemory":            8,
		"connectionEffectiveType": "4g",
		"notificationsPermission": "denied",
	}

	jsonBytes, _ := json.Marshal(device)
	return string(jsonBytes)
}

// performCaptchaCheck submits captcha answer and returns status payload
func (V *VKHandler) performCaptchaCheck(
	ctx context.Context,
	sessionToken string,
	adFP string,
	browserFP string,
	hash string,
	answerJSON string,
	cursor string,
	debugInfo string,
) (*captchaCheck, error) {
	values := common.NewValues(
		"session_token", sessionToken,
		"domain", "vk.com",
		"adFp", adFP,
		"accelerometer", "[]",
		"gyroscope", "[]",
		"motion", "[]",
		"cursor", cursor,
		"taps", "[]",
		"connectionRtt", "[]",
		"connectionDownlink", "[]",
		"browser_fp", browserFP,
		"hash", hash,
		"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON)),
		"debug_info", debugInfo,
		"access_token", "",
	)

	slog.Debug("captcha check values", "adFp", adFP, "cursor", cursor, "browser_fp", browserFP, "hash", hash, "answer", answerJSON, "debug_info", debugInfo)

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
	}
	if out.Status == "" {
		return nil, fmt.Errorf("captcha check status missing: %v", raw)
	}

	return out, nil
}

// solveCheckboxCaptcha solves the checkbox captcha variant
func (V *VKHandler) solveCheckboxCaptcha(
	ctx context.Context,
	sessionToken string,
	adFP string,
	browserFP string,
	hash string,
	debugInfo string,
) (string, error) {
	if _, err := V.captchaRequest(ctx, "captchaNotRobot.componentDone", common.NewValues(
		"session_token", sessionToken,
		"domain", "vk.com",
		"adFp", adFP,
		"browser_fp", browserFP,
		"device", generateDeviceInfo(),
		"access_token", "",
	)); err != nil {
		return "", fmt.Errorf("captcha componentDone failed: %w", err)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(time.Duration(400) * time.Millisecond):
	}

	/*
		type pt struct {
			X int `json:"x"`
			Y int `json:"y"`
		}
		cursor, _ := json.Marshal([]pt{{X: 920 + rand.Intn(20), Y: 560 + rand.Intn(20)}})
	*/

	cursor := "[]" // this works somehow kek

	check, err := V.performCaptchaCheck(ctx, sessionToken, adFP, browserFP, hash, "{}", cursor, debugInfo)
	if err != nil {
		return "", err
	}

	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaRateLimit
	}

	// retrying the same session will just hit error_limit immediately and cause account-level throttling
	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("%w: checkbox captcha rejected: status=%s", errCaptchaRateLimit, check.Status)
	}

	if check.SuccessToken == "" {
		return "", errors.New("captcha success token not found")
	}

	return check.SuccessToken, nil
}

// solveCaptchaPoW brute-forces SHA-256 hash prefix target for PoW captcha
func solveCaptchaPoW(input string, difficulty int) string {
	if input == "" || difficulty <= 0 {
		return ""
	}

	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10_000_000; nonce++ {
		sum := sha256.Sum256([]byte(input + strconv.Itoa(nonce)))
		hash := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hash, target) {
			return hash
		}
	}

	return ""
}

// solveSliderCaptcha solves the slider variant using ranked candidates
func (V *VKHandler) solveSliderCaptcha(
	ctx context.Context,
	sessionToken string,
	adFP string,
	browserFP string,
	hash string,
	settings string,
	debugInfo string,
) (string, error) {
	values := common.NewValues(
		"session_token", sessionToken,
		"domain", "vk.com",
		"adFp", adFP,
		"access_token", "",
		"captcha_settings", settings,
	)

	slog.Debug("vk captcha slider content request")
	resp, err := V.captchaRequest(ctx, "captchaNotRobot.getContent", values)
	if err != nil {
		return "", fmt.Errorf("slider getContent failed: %w", err)
	}

	puzzle, err := parseSliderPuzzle(resp)
	if err != nil {
		return "", err
	}
	slog.Debug("vk captcha slider puzzle decoded", "grid_size", puzzle.Size, "attempts", puzzle.Attempts, "swaps", len(puzzle.Swaps))

	guesses, err := rankSliderGuesses(puzzle.Image, puzzle.Size, puzzle.Swaps)
	if err != nil {
		return "", err
	}

	attemptLimit := min(puzzle.Attempts, len(guesses))
	slog.Debug("vk captcha slider guesses ranked", "guesses", len(guesses), "attempt_limit", attemptLimit)

	limit := attemptLimit
	if limit <= 0 {
		return "", errors.New("slider has no attempts available")
	}

	if _, err := V.captchaRequest(ctx, "captchaNotRobot.componentDone", common.NewValues(
		"session_token", sessionToken,
		"domain", "vk.com",
		"adFp", adFP,
		"access_token", "",
		"browser_fp", browserFP,
		"device", generateDeviceInfo(),
	)); err != nil {
		return "", fmt.Errorf("captcha componentDone failed: %w", err)
	}

	for i := 0; i < limit; i++ {
		slog.Debug("vk captcha slider attempt", "attempt", i+1, "max_attempts", limit, "guess_index", guesses[i].Index)
		answerData, err := json.Marshal(struct {
			Value []int `json:"value"`
		}{Value: guesses[i].Swaps})
		if err != nil {
			return "", err
		}
		answer := string(answerData)

		check, err := V.performCaptchaCheck(ctx, sessionToken, adFP, browserFP, hash, answer, buildSliderCursor(guesses[i].Index, len(guesses)), debugInfo)
		if err != nil {
			return "", err
		}

		if strings.EqualFold(check.Status, "ok") {
			slog.Debug("vk captcha slider accepted", "attempt", i+1)
			if check.SuccessToken == "" {
				return "", errors.New("captcha success token not found")
			}

			return check.SuccessToken, nil
		}

		if strings.EqualFold(check.Status, "error_limit") {
			return "", errCaptchaRateLimit
		}
	}

	return "", errors.New("slider guesses exhausted")
}

// parseSliderPuzzle decodes slider content payload into a puzzle model
func parseSliderPuzzle(raw map[string]any) (*sliderPuzzle, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid slider content response: %v", raw)
	}

	status := common.StringifyAny(resp["status"])
	if !strings.EqualFold(status, "ok") {
		return nil, fmt.Errorf("slider getContent status: %s", status)
	}

	rawImage := common.StringifyAny(resp["image"])
	if rawImage == "" {
		return nil, errors.New("slider image missing")
	}

	rawSteps, ok := resp["steps"].([]any)
	if !ok {
		return nil, errors.New("slider steps missing")
	}

	steps := make([]int, 0, len(rawSteps))
	for _, item := range rawSteps {
		switch value := item.(type) {
		case float64:
			steps = append(steps, int(value))
		case int:
			steps = append(steps, value)
		case string:
			number, convErr := strconv.Atoi(strings.TrimSpace(value))
			if convErr != nil {
				return nil, fmt.Errorf("invalid numeric value: %v", item)
			}
			steps = append(steps, number)
		default:
			return nil, fmt.Errorf("invalid numeric value: %v", item)
		}
	}

	size, swaps, attempts, err := splitSliderSteps(steps)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(rawImage)
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	return &sliderPuzzle{
		Image:    img,
		Size:     size,
		Swaps:    swaps,
		Attempts: attempts,
	}, nil
}

// splitSliderSteps separates grid size, swap list, and allowed attempts
func splitSliderSteps(steps []int) (size int, swaps []int, attempts int, err error) {
	if len(steps) < 3 {
		return 0, nil, 0, errors.New("slider steps payload too short")
	}

	size = steps[0]
	if size <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider size: %d", size)
	}

	tail := append([]int(nil), steps[1:]...)
	attempts = 4
	if len(tail)%2 != 0 {
		attempts = tail[len(tail)-1]
		tail = tail[:len(tail)-1]
	}
	if attempts <= 0 {
		attempts = 4
	}
	if len(tail) == 0 || len(tail)%2 != 0 {
		return 0, nil, 0, errors.New("invalid slider swap payload")
	}

	return size, tail, attempts, nil
}

// rankSliderGuesses scores all swap prefixes and returns best-first ordering
func rankSliderGuesses(img image.Image, gridSize int, swaps []int) ([]sliderGuess, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, errors.New("slider has no candidates")
	}

	guesses := make([]sliderGuess, candidateCount)
	for idx := 1; idx <= candidateCount; idx++ {
		active := activeSwapsForIndex(swaps, idx)
		tileMap, err := applySliderSwaps(gridSize, active)
		if err != nil {
			return nil, err
		}
		guesses[idx-1] = sliderGuess{
			Index: idx,
			Swaps: active,
		}
		guesses[idx-1].ScoreLuma = seamScoreLumaForMapping(img, gridSize, tileMap)
	}

	// Stage 1: cheap global rank on luma seam score
	lumaOrder := append([]sliderGuess(nil), guesses...)
	sort.SliceStable(lumaOrder, func(i, j int) bool {
		if lumaOrder[i].ScoreLuma == lumaOrder[j].ScoreLuma {
			return lumaOrder[i].Index < lumaOrder[j].Index
		}
		return lumaOrder[i].ScoreLuma < lumaOrder[j].ScoreLuma
	})

	lumaRank := make(map[int]int, candidateCount)
	for rank, guess := range lumaOrder {
		lumaRank[guess.Index] = rank
	}

	// Stage 2: expensive scoring only on best K from stage 1
	stage2Count := min(candidateCount, 12)
	stage2Set := make(map[int]struct{}, stage2Count)
	for i := 0; i < stage2Count; i++ {
		stage2Set[lumaOrder[i].Index] = struct{}{}
	}

	type stage2Score struct {
		index int
		rgb   int64
		text  float64
		err   error
	}

	workers := max(1, min(runtime.NumCPU(), candidateCount))
	jobCh := make(chan int, candidateCount)
	resCh := make(chan stage2Score, stage2Count)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobCh {
				index := i + 1
				if _, ok := stage2Set[index]; !ok {
					continue
				}
				mapping, err := applySliderSwaps(gridSize, guesses[i].Swaps)
				if err != nil {
					resCh <- stage2Score{index: index, err: err}
					continue
				}
				rgb, text := seamScoreRGBTextForMapping(img, gridSize, mapping)
				resCh <- stage2Score{index: index, rgb: rgb, text: text}
			}
		}()
	}
	for i := range guesses {
		jobCh <- i
	}
	close(jobCh)
	wg.Wait()
	close(resCh)

	for result := range resCh {
		if result.err != nil {
			return nil, result.err
		}
		g := &guesses[result.index-1]
		g.ScoreRGB = result.rgb
		g.ScoreText = result.text
	}

	stage2 := make([]sliderGuess, 0, stage2Count)
	for _, guess := range guesses {
		if _, ok := stage2Set[guess.Index]; ok {
			stage2 = append(stage2, guess)
		}
	}

	rgbOrder := append([]sliderGuess(nil), stage2...)
	sort.SliceStable(rgbOrder, func(i, j int) bool {
		if rgbOrder[i].ScoreRGB == rgbOrder[j].ScoreRGB {
			return rgbOrder[i].Index < rgbOrder[j].Index
		}
		return rgbOrder[i].ScoreRGB < rgbOrder[j].ScoreRGB
	})
	rgbRank := make(map[int]int, len(rgbOrder))
	for rank, guess := range rgbOrder {
		rgbRank[guess.Index] = rank
	}

	textOrder := append([]sliderGuess(nil), stage2...)
	sort.SliceStable(textOrder, func(i, j int) bool {
		if textOrder[i].ScoreText == textOrder[j].ScoreText {
			return textOrder[i].Index < textOrder[j].Index
		}
		return textOrder[i].ScoreText < textOrder[j].ScoreText
	})
	textRank := make(map[int]int, len(textOrder))
	for rank, guess := range textOrder {
		textRank[guess.Index] = rank
	}

	for i := range guesses {
		g := &guesses[i]
		g.ConsensusRank = lumaRank[g.Index]
		if _, ok := stage2Set[g.Index]; ok {
			g.ConsensusRank += rgbRank[g.Index] + textRank[g.Index]
		} else {
			// keep non-stage2 candidates behind fully scored set
			g.ConsensusRank += candidateCount
		}
		g.Score = int64(g.ConsensusRank)
	}

	sort.SliceStable(guesses, func(i, j int) bool {
		if guesses[i].ConsensusRank == guesses[j].ConsensusRank {
			if guesses[i].ScoreLuma == guesses[j].ScoreLuma {
				return guesses[i].Index < guesses[j].Index
			}
			return guesses[i].ScoreLuma < guesses[j].ScoreLuma
		}
		return guesses[i].ConsensusRank < guesses[j].ConsensusRank
	})

	return guesses, nil
}

// activeSwapsForIndex returns swap prefix representing one slider position
func activeSwapsForIndex(swaps []int, index int) []int {
	if index <= 0 {
		return []int{}
	}
	end := index * 2
	if end > len(swaps) {
		end = len(swaps)
	}
	return append([]int(nil), swaps[:end]...)
}

// applySliderSwaps constructs tile mapping for a swap sequence
func applySliderSwaps(gridSize int, swaps []int) ([]int, error) {
	tileCount := gridSize * gridSize
	if tileCount <= 0 {
		return nil, fmt.Errorf("invalid slider tile count: %d", tileCount)
	}
	if len(swaps)%2 != 0 {
		return nil, fmt.Errorf("invalid slider swaps length: %d", len(swaps))
	}

	mapping := make([]int, tileCount)
	for i := range mapping {
		mapping[i] = i
	}

	for i := 0; i < len(swaps); i += 2 {
		left := swaps[i]
		right := swaps[i+1]
		if left < 0 || right < 0 || left >= tileCount || right >= tileCount {
			return nil, fmt.Errorf("slider step out of range: %d,%d", left, right)
		}
		mapping[left], mapping[right] = mapping[right], mapping[left]
	}

	return mapping, nil
}

// seamScoreLumaForMapping computes luma seam score without rendering whole candidate image
func seamScoreLumaForMapping(img image.Image, gridSize int, mapping []int) int64 {
	bounds := img.Bounds()
	var score int64

	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			height := min(leftDst.Dy(), rightDst.Dy())
			for y := 0; y < height; y++ {
				yy := leftDst.Min.Y + y
				a := sampleLumaMapped(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				b := sampleLumaMapped(img, rightDst, rightSrc, rightDst.Min.X, yy)
				score += int64(absInt(int(a) - int(b)))
			}
		}
	}

	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			width := min(topDst.Dx(), bottomDst.Dx())
			for x := 0; x < width; x++ {
				xx := topDst.Min.X + x
				a := sampleLumaMapped(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleLumaMapped(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				score += int64(absInt(int(a) - int(b)))
			}
		}
	}

	return score
}

// seamScoreRGBTextForMapping computes RGB seam score and text-weighted seam score without full render
func seamScoreRGBTextForMapping(img image.Image, gridSize int, mapping []int) (int64, float64) {
	bounds := img.Bounds()
	height := float64(bounds.Dy())
	textCenters := []float64{
		float64(bounds.Min.Y) + 0.2*height,
		float64(bounds.Min.Y) + 0.5*height,
		float64(bounds.Min.Y) + 0.8*height,
	}
	sigma := max(1.0, height*0.14)
	weight := func(y int) float64 {
		yf := float64(y)
		best := absFloat(yf - textCenters[0])
		for i := 1; i < len(textCenters); i++ {
			d := absFloat(yf - textCenters[i])
			if d < best {
				best = d
			}
		}
		return 1 + 3*math.Exp(-(best*best)/(2*sigma*sigma))
	}

	var rgbScore int64
	var textScore float64

	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			heightPx := min(leftDst.Dy(), rightDst.Dy())
			for y := 0; y < heightPx; y++ {
				yy := leftDst.Min.Y + y
				l := sampleColorMapped(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				r := sampleColorMapped(img, rightDst, rightSrc, rightDst.Min.X, yy)
				rgbDelta := pixelDiff(l, r)
				rgbScore += rgbDelta
				_, _, lb, _ := l.RGBA()
				_, _, rb, _ := r.RGBA()
				textScore += weight(yy) * float64(absInt(int(lb>>8)-int(rb>>8)))
			}
		}
	}

	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			width := min(topDst.Dx(), bottomDst.Dx())
			for x := 0; x < width; x++ {
				xx := topDst.Min.X + x
				t := sampleColorMapped(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleColorMapped(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				rgbDelta := pixelDiff(t, b)
				rgbScore += rgbDelta
				_, _, tb, _ := t.RGBA()
				_, _, bb, _ := b.RGBA()
				textScore += 0.65 * float64(absInt(int(tb>>8)-int(bb>>8)))
			}
		}
	}

	return rgbScore, textScore
}

// sampleColorMapped samples source image color mapped from destination tile coordinates
func sampleColorMapped(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) color.Color {
	dx := max(1, dstRect.Dx())
	dy := max(1, dstRect.Dy())
	sx := srcRect.Min.X + (dstX-dstRect.Min.X)*srcRect.Dx()/dx
	sy := srcRect.Min.Y + (dstY-dstRect.Min.Y)*srcRect.Dy()/dy
	return img.At(sx, sy)
}

// sampleLumaMapped samples source image luma mapped from destination tile coordinates
func sampleLumaMapped(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) uint8 {
	c := sampleColorMapped(img, dstRect, srcRect, dstX, dstY)
	r, g, b, _ := c.RGBA()
	// Rec. 601 luma, convert from 16-bit channel space to 8-bit
	y := (299*(r>>8) + 587*(g>>8) + 114*(b>>8)) / 1000
	return uint8(y)
}

// absFloat returns absolute value for float64
func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// sliderTileRect returns tile rectangle by grid index
func sliderTileRect(bounds image.Rectangle, gridSize int, index int) image.Rectangle {
	row := index / gridSize
	col := index % gridSize

	x0 := bounds.Min.X + col*bounds.Dx()/gridSize
	x1 := bounds.Min.X + (col+1)*bounds.Dx()/gridSize
	y0 := bounds.Min.Y + row*bounds.Dy()/gridSize
	y1 := bounds.Min.Y + (row+1)*bounds.Dy()/gridSize
	return image.Rect(x0, y0, x1, y1)
}

// pixelDiff computes per-channel absolute color difference
func pixelDiff(left color.Color, right color.Color) int64 {
	lr, lg, lb, _ := left.RGBA()
	rr, rg, rb, _ := right.RGBA()
	return absDiff(lr, rr) + absDiff(lg, rg) + absDiff(lb, rb)
}

// absDiff returns absolute difference for two uint32 values
func absDiff(left uint32, right uint32) int64 {
	if left > right {
		return int64(left - right)
	}
	return int64(right - left)
}

// absInt returns absolute integer value
func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// buildSliderCursor generates a randomized cursor trajectory for slider answer
func buildSliderCursor(candidateIndex int, candidateCount int) string {
	if candidateCount <= 0 {
		return "[]"
	}
	if candidateIndex < 1 {
		candidateIndex = 1
	}
	if candidateIndex > candidateCount {
		candidateIndex = candidateCount
	}

	type cursorPoint struct {
		X int `json:"x"`
		Y int `json:"y"`
	}

	startX := 570 + rand.Intn(40)
	startY := 875 + rand.Intn(30)

	baseTargetX := 734 + (937-734)*(candidateIndex-1)/max(1, candidateCount-1)
	targetX := baseTargetX + rand.Intn(10) - 5
	targetY := 655 + rand.Intn(14)

	points := make([]cursorPoint, 0, 28)

	for i := 0; i < 1+rand.Intn(3); i++ {
		points = append(points, cursorPoint{
			X: startX + rand.Intn(5) - 2,
			Y: startY + rand.Intn(5) - 2,
		})
	}

	transitSteps := 2 + rand.Intn(3)
	arcOffX := rand.Intn(60) - 30
	arcOffY := -(rand.Intn(30) + 10)
	for i := 1; i <= transitSteps; i++ {
		t := float64(i) / float64(transitSteps+1)
		cx := float64(startX+targetX)/2 + float64(arcOffX)
		cy := float64(startY+targetY)/2 + float64(arcOffY)
		bx := (1-t)*(1-t)*float64(startX) + 2*t*(1-t)*cx + t*t*float64(targetX)
		by := (1-t)*(1-t)*float64(startY) + 2*t*(1-t)*cy + t*t*float64(targetY)
		jitter := int((1-t)*8) + 2
		points = append(points, cursorPoint{
			X: int(math.Round(bx)) + rand.Intn(jitter*2+1) - jitter,
			Y: int(math.Round(by)) + rand.Intn(jitter*2+1) - jitter,
		})
	}

	approachSteps := 4 + rand.Intn(4)
	prev := points[len(points)-1]
	for i := 1; i <= approachSteps; i++ {
		t := float64(i) / float64(approachSteps)
		ax := prev.X + int(math.Round(t*float64(targetX-prev.X))) + rand.Intn(5) - 2
		ay := prev.Y + int(math.Round(t*float64(targetY-prev.Y))) + rand.Intn(5) - 2
		points = append(points, cursorPoint{X: ax, Y: ay})
	}

	settleCount := 3 + rand.Intn(5)
	for i := 0; i < settleCount; i++ {
		points = append(points, cursorPoint{
			X: targetX + rand.Intn(7) - 3,
			Y: targetY + rand.Intn(7) - 3,
		})
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}
