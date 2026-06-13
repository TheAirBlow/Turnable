package vk

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"time"

	"github.com/theairblow/turnable/pkg/config"
	http "github.com/useflyent/fhttp"
)

//go:embed manual_captcha.user.js
var vkCaptchaUserScript []byte

const (
	manualCaptchaTimeout = 10 * time.Minute
	manualCaptchaPort    = "1984"
)

// manualCaptchaResult carries both tokens extracted from the VK join page flow
type manualCaptchaResult struct {
	messages string
	calls    string
}

// solveManualCaptcha starts a local token capture server and prompts the user to run a userscript
func (V *Handler) solveManualCaptcha(ctx context.Context, joinURL string) (string, string, error) {
	keyCh := make(chan manualCaptchaResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/manual_captcha.user.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(vkCaptchaUserScript)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://github.com/TheAirBlow/Turnable/blob/main/docs/VK.md", http.StatusFound)
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		mToken := r.URL.Query().Get("messages")
		aToken := r.URL.Query().Get("calls")
		if aToken != "" {
			select {
			case keyCh <- manualCaptchaResult{messages: mToken, calls: aToken}:
			default:
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Turnable</title>`+
			`<style>*{box-sizing:border-box}body{margin:0;display:flex;align-items:center;justify-content:center;`+
			`min-height:100vh;font-family:system-ui,sans-serif;background:#f0f4f8;color:#1a1a1a}`+
			`h2{margin:16px 0 8px;font-size:22px}p{margin:0;color:#666}</style></head>`+
			`<body><div style="text-align:center">`+
			`<div style="font-size:64px;line-height:1">✅</div>`+
			`<h2>Tokens captured</h2>`+
			`<p>You may close this tab.</p>`+
			`</div></body></html>`)
	})

	ln4, err := net.Listen("tcp", "127.0.0.1:"+manualCaptchaPort)
	if err != nil {
		return "", "", fmt.Errorf("manual captcha: port %s already in use (another instance running?): %w", manualCaptchaPort, err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln4); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("manual captcha server error", "error", err)
		}
	}()
	if ln6, err := net.Listen("tcp", "[::1]:"+manualCaptchaPort); err == nil {
		go func() {
			if err := srv.Serve(ln6); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Warn("manual captcha server error", "error", err)
			}
		}()
	}

	slog.Info("manual captcha solve required",
		"userscript", "http://localhost:"+manualCaptchaPort+"/manual_captcha.user.js",
		"guide", "http://localhost:"+manualCaptchaPort+"/",
		"url", joinURL,
		"timeout", manualCaptchaTimeout)

	if config.Options.Interactive {
		manualCaptchaOpenBrowser(joinURL)
	}

	var result manualCaptchaResult
	solveCtx, solveCancel := context.WithTimeout(ctx, manualCaptchaTimeout)
	defer solveCancel()

	select {
	case <-solveCtx.Done():
		if errors.Is(solveCtx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("manual captcha timed out after %s", manualCaptchaTimeout)
		} else {
			err = solveCtx.Err()
		}
	case result = <-keyCh:
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)

	return result.messages, result.calls, err
}

// manualCaptchaOpenBrowser tries to open the URL in a browser appropriate for the current platform
func manualCaptchaOpenBrowser(url string) {
	var cmds []struct {
		name string
		args []string
	}

	switch runtime.GOOS {
	case "windows":
		cmds = []struct {
			name string
			args []string
		}{{"cmd", []string{"/c", "start", url}}}
	case "darwin", "ios":
		cmds = []struct {
			name string
			args []string
		}{{"open", []string{url}}}
	case "android":
		cmds = []struct {
			name string
			args []string
		}{
			{"sh", []string{"-c", "termux-open-url " + url}},
			{"sh", []string{"-c", "/system/bin/am start -a android.intent.action.VIEW -d " + url}},
		}
	default:
		cmds = []struct {
			name string
			args []string
		}{
			{"xdg-open", []string{url}},
			{"gio", []string{"open", url}},
			{"sensible-browser", []string{url}},
		}
	}

	for _, c := range cmds {
		if err := exec.Command(c.name, c.args...).Start(); err == nil {
			return
		}
	}
}
