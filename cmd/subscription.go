package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/version"
)

const subscriptionMaxBody = 4 << 20 // upper bound for a subscription response

// subscription is a fetched subscription with its metadata headers
type subscription struct {
	Title      string
	Announce   string
	SupportURL string
	WebPage    string
	Used       int64 // bytes used (upload + download)
	Total      int64 // byte quota, 0 means unlimited
	Expire     int64 // unix expiry, 0 means never
	Options    []subscriptionOption
}

// subscriptionOption is one connection offered by a subscription
type subscriptionOption struct {
	Name string
	URL  string
}

// isSubscriptionURL reports whether raw is a single http(s) URL
func isSubscriptionURL(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	if strings.ContainsAny(s, "\r\n") {
		return false
	}

	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// fetchSubscription downloads and parses a subscription
func fetchSubscription(rawURL string) (*subscription, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	// The panel serves turnable:// links only to user agents it recognizes as Turnable apps
	req.Header.Set("User-Agent", "Turnable-Android/"+version.String()+" (cli)")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch subscription: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, subscriptionMaxBody))
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription: %w", err)
	}

	sub := &subscription{
		Title:      decodeHeader(resp.Header.Get("Profile-Title")),
		Announce:   decodeHeader(resp.Header.Get("Announce")),
		SupportURL: resp.Header.Get("Support-Url"),
		WebPage:    resp.Header.Get("Profile-Web-Page-Url"),
	}
	parseUserInfo(sub, resp.Header.Get("Subscription-Userinfo"))

	text := strings.TrimSpace(string(body))
	if !strings.Contains(text, "://") {
		if dec, err := base64.StdEncoding.DecodeString(text); err == nil {
			text = string(dec)
		}
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "turnable://") {
			continue
		}

		name := ""
		if cfg, err := config.ParseClientConfig([]byte(line)); err == nil {
			name = cfg.GetInner().(config.ClientConfig).Name
		}
		sub.Options = append(sub.Options, subscriptionOption{Name: name, URL: line})
	}

	if len(sub.Options) == 0 {
		return nil, fmt.Errorf("subscription has no turnable:// connections")
	}

	return sub, nil
}

// decodeHeader decodes a "base64:"-prefixed header value
func decodeHeader(v string) string {
	if enc, ok := strings.CutPrefix(v, "base64:"); ok {
		if dec, err := base64.StdEncoding.DecodeString(enc); err == nil {
			return string(dec)
		}
	}

	return v
}

// parseUserInfo reads a "upload=1; download=2; total=3; expire=4" Subscription-Userinfo header
func parseUserInfo(sub *subscription, v string) {
	for _, part := range strings.Split(v, ";") {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}

		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			continue
		}

		switch strings.TrimSpace(key) {
		case "upload", "download":
			sub.Used += n
		case "total":
			sub.Total = n
		case "expire":
			sub.Expire = n
		}
	}
}

// printSubscription shows the subscription details and numbered options
func printSubscription(sub *subscription) {
	title := sub.Title
	if common.IsNullOrWhiteSpace(title) {
		title = "Subscription"
	}

	fmt.Printf("%s\n", title)
	if sub.Total > 0 {
		fmt.Printf("  Traffic:  %s of %s used\n", formatBytes(sub.Used), formatBytes(sub.Total))
	} else {
		fmt.Printf("  Traffic:  %s used, unlimited\n", formatBytes(sub.Used))
	}
	if sub.Expire > 0 {
		fmt.Printf("  Expires:  %s\n", time.Unix(sub.Expire, 0).Format("2006-01-02 15:04"))
	}
	if sub.SupportURL != "" {
		fmt.Printf("  Support:  %s\n", sub.SupportURL)
	}
	if sub.WebPage != "" {
		fmt.Printf("  Web page: %s\n", sub.WebPage)
	}
	if sub.Announce != "" {
		fmt.Printf("  Notice:   %s\n", sub.Announce)
	}

	fmt.Println("\nAvailable connections:")
	for i, opt := range sub.Options {
		name := opt.Name
		if common.IsNullOrWhiteSpace(name) {
			name = "Connection " + strconv.Itoa(i+1)
		}
		fmt.Printf("  %d. %s\n", i+1, name)
	}
}

// formatBytes renders a byte count with a binary unit suffix
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// optionRange renders the valid choices as [1] or [1-n]
func optionRange(n int) string {
	if n == 1 {
		return "[1]"
	}

	return fmt.Sprintf("[1-%d]", n)
}

// chooseSubscriptionOption prompts until the user picks a connection, returning its URL
func chooseSubscriptionOption(sub *subscription) (string, error) {
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("\nSelect a connection %s: ", optionRange(len(sub.Options)))
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)

		if n, convErr := strconv.Atoi(line); convErr == nil && n >= 1 && n <= len(sub.Options) {
			return sub.Options[n-1].URL, nil
		}

		if err != nil {
			return "", fmt.Errorf("no connection selected: %w", err)
		}
		fmt.Println("Invalid choice")
	}
}

// resolveSubscription fetches the subscription at rawURL and returns the chosen turnable:// URL
func resolveSubscription(rawURL string) ([]byte, error) {
	if !config.Options.Interactive {
		return nil, fmt.Errorf("subscriptions require interactive mode")
	}

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}

	sub, err := fetchSubscription(u.String())
	if err != nil {
		return nil, err
	}

	printSubscription(sub)
	chosen, err := chooseSubscriptionOption(sub)
	if err != nil {
		return nil, err
	}

	return []byte(chosen), nil
}
