package platform

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const manualCaptchaTimeout = 60 * time.Second

// manualCaptchaWrapperHTML is the outer page served to the user
const manualCaptchaWrapperHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Turnable | VK CAPTCHA</title>
  <style>html, body { margin: 0; padding: 0; width: 100%%; height: 100%%; overflow: hidden; }</style>
  <script>
    (function() {
      var origDescriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "src") ||
                           Object.getOwnPropertyDescriptor(Element.prototype, "src");
      if (!origDescriptor || !origDescriptor.set) return;
      Object.defineProperty(HTMLIFrameElement.prototype, "src", {
        get: origDescriptor.get,
        set: function(val) {
          try {
            var u = new URL(val);
            u.searchParams.set("origin", location.origin);
            val = u.href;
          } catch (e) {}
          origDescriptor.set.call(this, val);
        },
        configurable: true,
      });
    })();
  </script>
</head>
<body>
  <script src="https://static.vk.com/captchaSDK/loader/0/umd/index.js"></script>
  <script>
    window.vkidCaptchaInit.then(function(CaptchaWidget) {
      return new CaptchaWidget().show({
        container: document.body,
        iframeSrc: %q,
        view: "popup",
      });
    }).then(function(token) {
      return fetch("/captcha-result", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "token=" + encodeURIComponent(token),
      });
    }).then(function() {
      document.body.innerHTML = "<h2 style='text-align:center;margin-top:20vh'>Done! You can close this tab.</h2>";
    }).catch(function(err) {
      if (err !== "close") {
        document.body.innerHTML = "<h2 style='text-align:center;margin-top:20vh'>Error: " + err + "</h2>";
      }
    });
  </script>
</body>
</html>`

// manualCaptchaIsLocalHost reports whether host matches one of the localhost variants on the given port
func manualCaptchaIsLocalHost(host, port string) bool {
	for _, h := range []string{"localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port} {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// manualCaptchaRewriteRequest rewrites an outbound proxy request to target the upstream VK host
func manualCaptchaRewriteRequest(req *http.Request, targetURL *neturl.URL, port string) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	if req.URL.Path == "" {
		req.URL.Path = targetURL.Path
	}
	req.Host = targetURL.Host
	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")
	for _, name := range []string{"Origin", "Referer"} {
		raw := req.Header.Get(name)
		if raw == "" {
			continue
		}
		parsed, err := neturl.Parse(raw)
		if err != nil || !manualCaptchaIsLocalHost(parsed.Host, port) {
			req.Header.Del(name)
			continue
		}
		parsed.Scheme = targetURL.Scheme
		parsed.Host = targetURL.Host
		req.Header.Set(name, parsed.String())
	}
}

// manualCaptchaRewriteRedirect rewrites a Location header from upstream back to localhost
func manualCaptchaRewriteRedirect(loc string, targetURL *neturl.URL, port string) (string, bool) {
	if loc != "" && loc[0] == '/' {
		if len(loc) > 1 && (loc[1] == '/' || loc[1] == '\\') {
			return "", false
		}
		return loc, true
	}
	parsed, err := neturl.Parse(loc)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, targetURL.Scheme) || !strings.EqualFold(parsed.Host, targetURL.Host) {
		return "", false
	}
	return (&neturl.URL{Scheme: "http", Host: "localhost:" + port, Path: parsed.Path, RawQuery: parsed.RawQuery}).String(), true
}

// manualCaptchaRewriteCookies strips domain/secure/partitioned and relaxes SameSite on all Set-Cookie headers
func manualCaptchaRewriteCookies(header http.Header) {
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Domain = ""
		c.Secure = false
		c.Partitioned = false
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteStrictMode {
			c.SameSite = http.SameSiteLaxMode
		}
		header.Add("Set-Cookie", c.String())
	}
}

// manualCaptchaExtractToken parses a captchaNotRobot.check response body and returns the success_token
func manualCaptchaExtractToken(body []byte) string {
	var payload struct {
		Response struct {
			SuccessToken string `json:"success_token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Response.SuccessToken
}

// manualCaptchaInjectShim injects JS into HTML to intercept captchaNotRobot.check and reroute URLs through the local proxy
func manualCaptchaInjectShim(html, localOrigin, upstreamOrigin string) string {
	shim := fmt.Sprintf(`<script>
(function() {
    var localOrigin = %q;
    var upstreamOrigin = %q;

    function rewriteUrl(u) {
        if (!u || typeof u !== "string") return u;
        if (u.indexOf(localOrigin) === 0) return u;
        if (u.indexOf(upstreamOrigin) === 0) return localOrigin + u.slice(upstreamOrigin.length);
        if (u.indexOf("//") === 0) return "/proxy?url=" + encodeURIComponent("https:" + u);
        if (u.indexOf("http://") === 0 || u.indexOf("https://") === 0) return "/proxy?url=" + encodeURIComponent(u);
        return u;
    }

    function handleToken(token) {
        if (!token) return;
        fetch("/captcha-result", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "token=" + encodeURIComponent(token),
        }).then(function() {
            document.body.innerHTML = "<h2 style=\"text-align:center;margin-top:20vh\">Done! You can close this tab.</h2>";
        }).catch(function() {});
    }

    function tryExtractToken(text) {
        try {
            var data = JSON.parse(text);
            if (data.response && data.response.success_token) handleToken(data.response.success_token);
        } catch (e) {}
    }

    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        if (typeof arguments[1] === "string") {
            this._origUrl = arguments[1];
            arguments[1] = rewriteUrl(arguments[1]);
        }
        return origOpen.apply(this, arguments);
    };

    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        if (this._origUrl && this._origUrl.indexOf("captchaNotRobot.check") !== -1) {
            this.addEventListener("load", function() { tryExtractToken(this.responseText); });
        }
        return origSend.apply(this, arguments);
    };

    if (window.fetch) {
        var origFetch = window.fetch;
        window.fetch = function() {
            var url = typeof arguments[0] === "string" ? arguments[0] : (arguments[0] && arguments[0].url) || "";
            if (typeof arguments[0] === "string") arguments[0] = rewriteUrl(arguments[0]);
            var p = origFetch.apply(this, arguments);
            if (url.indexOf("captchaNotRobot.check") !== -1) {
                p.then(function(r) { return r.clone().text(); }).then(tryExtractToken).catch(function() {});
            }
            return p;
        };
    }
})();
</script>`, localOrigin, upstreamOrigin)

	switch {
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", shim+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", shim+"</body>", 1)
	default:
		return html + shim
	}
}

// solveManualCaptcha starts a local reverse proxy for the VK captcha page, waits up to manualCaptchaTimeout for the user to solve it
func (V *VKHandler) solveManualCaptcha(ctx context.Context, apiErr vkAPIError) (string, error) {
	if apiErr.RedirectURI == "" {
		return "", errors.New("manual captcha: missing redirect URI")
	}
	targetURL, err := neturl.Parse(apiErr.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("manual captcha: invalid redirect URI: %w", err)
	}

	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("manual captcha: failed to bind: %w", err)
	}
	port := fmt.Sprint(ln4.Addr().(*net.TCPAddr).Port)
	localOrigin := "http://localhost:" + port
	upstreamOrigin := targetURL.Scheme + "://" + targetURL.Host
	keyCh := make(chan string, 1)

	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			manualCaptchaRewriteRequest(req.Out, targetURL, port)
		},
		ModifyResponse: func(res *http.Response) error {
			manualCaptchaRewriteCookies(res.Header)
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					if rewritten, ok := manualCaptchaRewriteRedirect(loc, targetURL, port); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			contentType := res.Header.Get("Content-Type")
			isHTML := strings.Contains(contentType, "text/html")
			isCaptchaCheck := strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")
			if !isHTML && !isCaptchaCheck {
				return nil
			}

			reader := io.Reader(res.Body)
			if res.Header.Get("Content-Encoding") == "gzip" {
				gz, gzErr := gzip.NewReader(res.Body)
				if gzErr == nil {
					defer gz.Close()
					reader = gz
				}
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			_ = res.Body.Close()

			if isCaptchaCheck {
				if tok := manualCaptchaExtractToken(body); tok != "" {
					select {
					case keyCh <- tok:
					default:
					}
				}
			}

			if isHTML {
				for _, h := range []string{
					"Content-Security-Policy", "Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy", "X-WebKit-CSP", "X-Frame-Options",
					"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy", "Strict-Transport-Security", "Alt-Svc",
				} {
					res.Header.Del(h)
				}
				body = []byte(manualCaptchaInjectShim(string(body), localOrigin, upstreamOrigin))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(body))
			res.ContentLength = int64(len(body))
			res.Header.Set("Content-Length", fmt.Sprint(len(body)))
			return nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/captcha-result", func(w http.ResponseWriter, r *http.Request) {
		if tok := r.FormValue("token"); tok != "" {
			select {
			case keyCh <- tok:
			default:
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		rawTarget := r.URL.Query().Get("url")
		parsedTarget, err := neturl.Parse(rawTarget)
		if err != nil || parsedTarget.Host == "" {
			http.Error(w, "bad url", http.StatusBadRequest)
			return
		}
		gp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL = parsedTarget
				req.Out.Host = parsedTarget.Host
				req.Out.Header.Del("Accept-Encoding")
				req.Out.Header.Del("TE")
			},
		}
		gp.ServeHTTP(w, r)
	})
	localIframeSrc := (&neturl.URL{
		Scheme: "http", Host: "localhost:" + port,
		Path: targetURL.Path, RawQuery: targetURL.RawQuery,
	}).String()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, manualCaptchaWrapperHTML, localIframeSrc)
			return
		}
		proxy.ServeHTTP(w, r)
	})

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

	localURL := localOrigin + "/"
	slog.Info("manual captcha required", "url", localURL, "timeout", manualCaptchaTimeout)

	V.mu.RLock()
	interactive := V.interactive
	V.mu.RUnlock()
	if interactive {
		manualCaptchaOpenBrowser(localURL)
	}

	var token string
	solveCtx, solveCancel := context.WithTimeout(ctx, manualCaptchaTimeout)
	defer solveCancel()
	select {
	case <-solveCtx.Done():
		if errors.Is(solveCtx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("manual captcha timed out after %s", manualCaptchaTimeout)
		} else {
			err = solveCtx.Err()
		}
	case token = <-keyCh:
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
	return token, err
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
			{"termux-open-url", []string{url}},
			{"/system/bin/am", []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{"am", []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
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
