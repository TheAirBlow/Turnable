package config

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
)

// ClientConfig represents a client configuration
type ClientConfig struct {
	UserUUID string `json:"user_uuid,omitempty"` // User's unique UUID
	Username string `json:"username,omitempty"`  // [-] Username to use in the call

	PlatformID string `json:"platform_id,omitempty"` // [-] ID of the platform
	CallID     string `json:"call_id,omitempty"`     // [-] ID of the call on the platform

	Routes          []ClientRoute `json:"routes,omitempty"`           // Ordered list of tunnel routes
	GatewayUsername string        `json:"gateway_username,omitempty"` // [-] Gateway username in the call (P2P)

	Type      string `json:"type,omitempty"` // Connection type
	ForceTurn bool   `json:"forceturn"`      // [-] Force TURN in P2P mode
	Peers     int    `json:"peers"`          // [-] Peer connections per session

	Proto   string `json:"proto,omitempty"`   // [-] Protocol to use
	Cloak   string `json:"cloak,omitempty"`   // [-] Cloak method
	Gateway string `json:"gateway,omitempty"` // [-] Gateway's IP and port (Relay)

	PubKey     string `json:"pub_key,omitempty"`    // [-] Public key of the server
	Encryption string `json:"encryption,omitempty"` // Encryption mode

	Name string `json:"name,omitempty"` // [-] Display name
}

// ClientRoute represents one tunnel route inside a multi-route client config
type ClientRoute struct {
	RouteID   string `json:"route_id"`            // Route's unique ID
	Socket    string `json:"socket"`              // Socket protocol to use
	Transport string `json:"transport,omitempty"` // Transport protocol to use
}

// Validate checks that the ClientConfig contains all required fields.
func (c *ClientConfig) Validate() error {
	if common.IsNullOrWhiteSpace(c.Username) {
		return errors.New("username is required")
	}
	if common.IsNullOrWhiteSpace(c.CallID) {
		return errors.New("call_id is required")
	}

	if c.Proto == "" {
		c.Proto = "none"
	}
	if c.Cloak == "" {
		c.Cloak = "none"
	}

	if len(c.Routes) == 0 {
		return errors.New("at least one route is required")
	}

	if c.Type != "direct" {
		_, err := uuid.Parse(c.UserUUID)
		if err != nil {
			return fmt.Errorf("invalid user uuid: %s", c.UserUUID)
		}

		switch c.Encryption {
		case "handshake", "full":
		default:
			return fmt.Errorf("invalid encryption mode: %s", c.Encryption)
		}

		pubBytes, err := base64.StdEncoding.DecodeString(c.PubKey)
		if err != nil {
			return err
		}

		_, err = mlkem.NewEncapsulationKey768(pubBytes)
		if err != nil {
			return fmt.Errorf("invalid PQC public key structure: %w", err)
		}
	}

	if !common.PlatformsHolder.Exists(c.PlatformID) {
		return fmt.Errorf("invalid platform id: %s", c.PlatformID)
	}

	if !common.ConnectionsHolder.Exists(c.Type) {
		return fmt.Errorf("invalid connection type: %s", c.Type)
	}

	if c.Type == "relay" && !common.ProtocolsHolder.Exists(c.Proto) {
		return fmt.Errorf("invalid protocol: %s", c.Proto)
	}

	if len(c.Routes) == 0 {
		return errors.New("at least one route is required")
	}

	for i, route := range c.Routes {
		if common.IsNullOrWhiteSpace(route.RouteID) {
			return fmt.Errorf("routes[%d].route_id is required", i)
		}

		if c.Routes[i].Transport == "" {
			c.Routes[i].Transport = "none"
		}

		switch route.Socket {
		case "tcp", "udp":
		default:
			return fmt.Errorf("routes[%d]: invalid socket %q (must be tcp or udp)", i, route.Socket)
		}

		if route.Socket == "tcp" && c.Routes[i].Transport == "none" {
			return fmt.Errorf("routes[%d]: transport is required for tcp to work reliably", i)
		}

		if !common.TransportsHolder.Exists(c.Routes[i].Transport) {
			return fmt.Errorf("routes[%d]: invalid transport: %s", i, c.Routes[i].Transport)
		}
	}

	if c.Peers <= 0 {
		return fmt.Errorf("invalid peers count: %d (must be >= 1)", c.Peers)
	}

	if !common.IsNullOrWhiteSpace(c.Gateway) {
		host, port, err := net.SplitHostPort(c.Gateway)
		if err != nil {
			return fmt.Errorf("invalid gateway address format '%s': %v (expected ip:port)", c.Gateway, err)
		}
		if common.IsNullOrWhiteSpace(host) || common.IsNullOrWhiteSpace(port) {
			return errors.New("gateway ip or port is missing")
		}
	}

	return nil
}

// NewClientConfigFromJSON creates a new ClientConfig from a config JSON.
func NewClientConfigFromJSON(baseJSON string) (*ClientConfig, error) {
	var s ClientConfig
	if err := json.Unmarshal([]byte(baseJSON), &s); err != nil {
		return nil, fmt.Errorf("failed to parse client config: %w", err)
	}
	return &s, nil
}

// NewClientConfigFromURL parses a connection URL into a ClientConfig
func NewClientConfigFromURL(raw string) (*ClientConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "turnable" {
		return nil, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	q := u.Query()

	cfg := &ClientConfig{
		ForceTurn:  false,
		Cloak:      "none",
		Proto:      "dtls",
		Peers:      1,
		PlatformID: u.Host,
		Name:       u.Fragment,
	}

	if u.User != nil {
		cfg.UserUUID = u.User.Username()
		cfg.CallID, _ = u.User.Password()
	}

	path := strings.TrimPrefix(u.Path, "/")
	var routeIDs []string
	for _, seg := range strings.Split(path, "/") {
		if seg = strings.TrimSpace(seg); seg != "" {
			routeIDs = append(routeIDs, seg)
		}
	}

	sockets := make(map[int]string)
	transports := make(map[int]string)
	for key, vals := range q {
		if len(vals) == 0 {
			continue
		}

		val := vals[0]
		if bracket := strings.Index(key, "["); bracket >= 0 && strings.HasSuffix(key, "]") {
			name := key[:bracket]
			idxStr := key[bracket+1 : len(key)-1]
			if idx, err := strconv.Atoi(idxStr); err == nil && idx >= 1 {
				switch name {
				case "socket":
					sockets[idx] = val
				case "transport":
					transports[idx] = val
				}
			}
		} else {
			switch key {
			case "socket":
				sockets[1] = val
			case "transport":
				transports[1] = val
			}
		}
	}

	cfg.Routes = make([]ClientRoute, len(routeIDs))
	for i, rid := range routeIDs {
		idx := i + 1
		socket := sockets[idx]
		if socket == "" {
			socket = "udp"
		}

		transport := transports[idx]
		if transport == "" {
			transport = "none"
		}

		cfg.Routes[i] = ClientRoute{RouteID: rid, Socket: socket, Transport: transport}
	}

	if v := q.Get("username"); v != "" {
		cfg.Username = v
	}
	if v := q.Get("type"); v != "" {
		cfg.Type = v
	}
	if v := q.Get("gateway"); v != "" {
		cfg.Gateway = v
	}
	if v := q.Get("gateway_username"); v != "" {
		cfg.GatewayUsername = v
	}
	if v := q.Get("proto"); v != "" {
		cfg.Proto = v
	}
	if v := q.Get("cloak"); v != "" {
		cfg.Cloak = v
	}
	if v := q.Get("forceturn"); v != "" {
		cfg.ForceTurn, _ = strconv.ParseBool(v)
	}
	if v := q.Get("peers"); v != "" {
		cfg.Peers, _ = strconv.Atoi(v)
	}
	if v := q.Get("pub_key"); v != "" {
		cfg.PubKey = v
	}
	if v := q.Get("encryption"); v != "" {
		cfg.Encryption = v
	}

	if cfg.Proto == "" {
		cfg.Proto = "none"
	}
	if cfg.Cloak == "" {
		cfg.Cloak = "none"
	}

	return cfg, nil
}

// ToURL serialises the ClientConfig back into a connection URL
func (c *ClientConfig) ToURL() string {
	var pathParts []string
	for _, r := range c.Routes {
		pathParts = append(pathParts, strings.TrimPrefix(r.RouteID, "/"))
	}
	routePath := "/"
	if len(pathParts) > 0 {
		routePath = "/" + strings.Join(pathParts, "/")
	}

	u := &url.URL{
		Scheme:   "turnable",
		Host:     c.PlatformID,
		Path:     routePath,
		Fragment: c.Name,
	}

	if !common.IsNullOrWhiteSpace(c.UserUUID) || !common.IsNullOrWhiteSpace(c.CallID) {
		u.User = url.UserPassword(c.UserUUID, c.CallID)
	}

	type queryParam struct{ key, value string }
	params := make([]queryParam, 0, 16)

	single := len(c.Routes) == 1
	for i, r := range c.Routes {
		idx := i + 1

		var sockKey, transKey string
		if single {
			sockKey, transKey = "socket", "transport"
		} else {
			sockKey = fmt.Sprintf("socket[%d]", idx)
			transKey = fmt.Sprintf("transport[%d]", idx)
		}

		params = append(params, queryParam{sockKey, r.Socket})
		if !common.IsNullOrWhiteSpace(r.Transport) && r.Transport != "none" {
			params = append(params, queryParam{transKey, r.Transport})
		}
	}

	if !common.IsNullOrWhiteSpace(c.PubKey) {
		params = append(params, queryParam{"pub_key", c.PubKey})
	}
	if !common.IsNullOrWhiteSpace(c.Username) {
		params = append(params, queryParam{"username", c.Username})
	}
	if !common.IsNullOrWhiteSpace(c.Type) {
		params = append(params, queryParam{"type", c.Type})
	}
	if !common.IsNullOrWhiteSpace(c.Encryption) {
		params = append(params, queryParam{"encryption", c.Encryption})
	}
	if !common.IsNullOrWhiteSpace(c.Gateway) {
		params = append(params, queryParam{"gateway", c.Gateway})
	}
	if !common.IsNullOrWhiteSpace(c.GatewayUsername) {
		params = append(params, queryParam{"gateway_username", c.GatewayUsername})
	}
	if !common.IsNullOrWhiteSpace(c.Proto) && c.Proto != "none" {
		params = append(params, queryParam{"proto", c.Proto})
	}
	if !common.IsNullOrWhiteSpace(c.Cloak) && c.Cloak != "none" {
		params = append(params, queryParam{"cloak", c.Cloak})
	}
	if c.ForceTurn {
		params = append(params, queryParam{"forceturn", "true"})
	}
	if c.Peers > 1 {
		params = append(params, queryParam{"peers", strconv.Itoa(c.Peers)})
	}

	if len(params) > 0 {
		var b strings.Builder
		for i, p := range params {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(p.key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(p.value))
		}
		u.RawQuery = b.String()
	}

	return u.String()
}

// ToJSON serializes this ClientConfig to JSON
func (c *ClientConfig) ToJSON(stripped bool) (string, error) {
	if stripped {
		data := struct {
			UserUUID   string        `json:"user_uuid"`
			Routes     []ClientRoute `json:"routes"`
			Type       string        `json:"type"`
			Encryption string        `json:"encryption"`
		}{
			UserUUID:   c.UserUUID,
			Routes:     c.Routes,
			Type:       c.Type,
			Encryption: c.Encryption,
		}

		b, err := json.Marshal(data)
		if err != nil {
			return "", err
		}

		return string(b), nil
	}

	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
