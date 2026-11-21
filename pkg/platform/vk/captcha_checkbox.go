package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

// captchaPoint is a cursor position inside the captcha frame
type captchaPoint struct {
	X int `json:"x"` // Horizontal position in CSS pixels
	Y int `json:"y"` // Vertical position in CSS pixels
}

// solveCheckboxCaptcha solves the checkbox captcha variant
func (V *Handler) solveCheckboxCaptcha(ctx context.Context, session *captchaSession) (string, error) {
	if err := V.captchaComponentDone(ctx, session); err != nil {
		return "", err
	}

	cursor, hover := V.checkboxCursor(session.SensorsDelay)
	if err := sleepCtx(ctx, randomDuration(300, 1100)+hover); err != nil {
		return "", err
	}

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

// checkboxCursor samples the mouse path to the checkbox and the hover time before the click
func (V *Handler) checkboxCursor(intervalMs int) (string, time.Duration) {
	p := V.browserProfile()

	// The checkbox sits left of the frame center.
	target := captchaPoint{
		X: p.InnerWidth/2 - 32 + rand.Intn(25) - 12,
		Y: p.InnerHeight/2 + 62 + rand.Intn(13) - 6,
	}

	samples := 2 + rand.Intn(3) + rand.Intn(3)
	points := make([]captchaPoint, samples)

	if samples == 2 && rand.Intn(2) == 0 {
		points[0], points[1] = target, target
	} else {
		start := captchaPoint{
			X: min(max(target.X+(150+rand.Intn(350))*(2*rand.Intn(2)-1), 0), p.InnerWidth-1),
			Y: min(max(target.Y+(100+rand.Intn(250))*(2*rand.Intn(2)-1), 0), p.InnerHeight-1),
		}
		arc := float64(rand.Intn(80) - 40)

		for i := range points {
			t := float64(i) / float64(samples-1)
			eased := 1 - math.Pow(1-t, 2.5)
			bend := math.Sin(math.Pi*t) * arc
			noise := int((1 - t) * 4)

			points[i] = captchaPoint{
				X: start.X + int(math.Round(float64(target.X-start.X)*eased+bend)) + jitter(noise),
				Y: start.Y + int(math.Round(float64(target.Y-start.Y)*eased-bend)) + jitter(noise),
			}
		}

		points[samples-1] = target
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]", 0
	}

	hover := time.Duration((samples-1)*intervalMs)*time.Millisecond + randomDuration(60, 200)
	return string(data), hover
}

// jitter returns a random offset in [-n, n]
func jitter(n int) int {
	if n <= 0 {
		return 0
	}

	return rand.Intn(2*n+1) - n
}
