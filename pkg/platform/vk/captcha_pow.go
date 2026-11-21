package vk

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// captchaPowResult is the proof-of-work envelope the page script produces
type captchaPowResult struct {
	Hash       string          `json:"hash"`        // Proof-of-work hash
	Nonce      int             `json:"nonce"`       // Nonce that solves the proof of work
	Error      string          `json:"error"`       // Script error, empty when the proof of work finished
	DurationMs int64           `json:"duration_ms"` // Time the script ran, in milliseconds
	Telemetry  json.RawMessage `json:"telemetry"`   // Browser telemetry sent with the solution
	TelHash    string          `json:"tel_hash"`    // Hash of the telemetry
}

// buildCaptchaPoW solves the challenge and assembles the hash envelope with the time a browser would finish it
func (V *Handler) buildCaptchaPoW(page *captchaPage, navigatedAt time.Time) (string, time.Time, error) {
	hash, nonce := solveCaptchaPoW(page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", time.Time{}, errors.New("no solution found")
	}

	// The page script starts after the document and its blocking scripts have loaded.
	startOffset := float64(time.Since(navigatedAt).Milliseconds()) + float64(randomDuration(250, 900).Milliseconds())

	telemetry, telemetryMs := runCaptchaTelemetry(V.browserProfile(), page, navigatedAt, startOffset)
	telemetryJSON, err := marshalCaptchaJSON(telemetry)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to encode telemetry: %w", err)
	}

	telHash, err := hashCaptchaTelemetry(telemetryJSON)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to hash telemetry: %w", err)
	}

	// A browser hashes about 20k nonces per second next to the telemetry probes.
	durationMs := math.Round(math.Max(telemetryMs, float64(nonce+1)*0.05))

	envelope, err := marshalCaptchaJSON(captchaPowResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: int64(durationMs),
		Telemetry:  telemetryJSON,
		TelHash:    telHash,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to encode envelope: %w", err)
	}

	readyAt := navigatedAt.Add(time.Duration((startOffset + durationMs) * float64(time.Millisecond)))
	return "v2." + base64.StdEncoding.EncodeToString(escapeCaptchaNonASCII(envelope)), readyAt, nil
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

// hashCaptchaTelemetry hashes the telemetry with its keys sorted, as the page script does
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

// escapeCaptchaNonASCII replaces non-ASCII characters with \u escapes before the envelope is base64 encoded
func escapeCaptchaNonASCII(data []byte) []byte {
	var out bytes.Buffer
	for _, r := range string(data) {
		if r < 0x80 {
			out.WriteRune(r)
			continue
		}

		for _, unit := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&out, `\u%04x`, unit)
		}
	}

	return out.Bytes()
}
