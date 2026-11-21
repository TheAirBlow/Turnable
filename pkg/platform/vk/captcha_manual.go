package vk

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/config"
	http "github.com/useflyent/fhttp"
)

//go:embed captcha_manual.user.js
var vkCaptchaUserScript []byte

const (
	manualCaptchaTimeout = 10 * time.Minute // how long the user has to solve the captcha
	manualCaptchaOpened  = 5 * time.Minute  // minimum time left once the user opens the call page
	manualCaptchaPort    = "1984"           // local port of the captcha page
)

// manualCaptchaResult carries both tokens extracted from the VK join page flow
type manualCaptchaResult struct {
	messages string // token for the messages API
	calls    string // token for the calls API
}

// solveManualCaptcha starts a local token capture server and prompts the user to run a userscript
func (V *Handler) solveManualCaptcha(ctx context.Context, joinURL string) (string, string, error) {
	keyCh := make(chan manualCaptchaResult, 1)

	started := time.Now()
	var deadline atomic.Int64
	deadline.Store(started.Add(manualCaptchaTimeout).UnixNano())

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		// The userscript pings when the call page opens, so the user gets time to finish
		want := time.Now().Add(manualCaptchaOpened).UnixNano()
		for cur := deadline.Load(); cur < want; cur = deadline.Load() {
			if deadline.CompareAndSwap(cur, want) {
				slog.Debug("manual captcha timeout extended", "left", manualCaptchaOpened)
				break
			}
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/captcha_manual.user.js", func(w http.ResponseWriter, r *http.Request) {
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

	_, managed := os.LookupEnv("VK_MANUAL_MANAGED")
	port := manualCaptchaPort
	if managed {
		port = "0"
	}

	ln4, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return "", "", fmt.Errorf("manual captcha: port %s already in use (another instance running?): %w", port, err)
	}

	port = strconv.Itoa(ln4.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln4); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("manual captcha server error", "error", err)
		}
	}()
	if ln6, err := net.Listen("tcp", "[::1]:"+port); err == nil {
		go func() {
			if err := srv.Serve(ln6); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Warn("manual captcha server error", "error", err)
			}
		}()
	}

	if managed {
		slog.Info("manual captcha solve required",
			"port", port,
			"url", joinURL,
			"timeout", manualCaptchaTimeout)
	} else {
		slog.Info("manual captcha solve required",
			"userscript", "http://localhost:"+port+"/captcha_manual.user.js",
			"guide", "http://localhost:"+port+"/",
			"url", joinURL,
			"timeout", manualCaptchaTimeout)
	}

	if config.Options.Interactive {
		manualCaptchaOpenBrowser(joinURL)
	}

	var result manualCaptchaResult
wait:
	for {
		timer := time.NewTimer(time.Until(time.Unix(0, deadline.Load())))
		select {
		case <-ctx.Done():
			err = ctx.Err()
			timer.Stop()
			break wait
		case result = <-keyCh:
			timer.Stop()
			break wait
		case <-timer.C:
			// The deadline may have been extended while waiting
			if time.Now().UnixNano() >= deadline.Load() {
				err = fmt.Errorf("manual captcha timed out after %s", time.Since(started).Round(time.Second))
				break wait
			}
		}
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
