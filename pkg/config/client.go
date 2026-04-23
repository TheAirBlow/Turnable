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

// ClientConfig represents a client configuration URL
type ClientConfig struct {
	UserUUID string `json:"user_uuid"` // User's unique UIID
	Username string `json:"username"`  // [-] Username to use in the call

	PlatformID string `json:"platform_id"` // [-] ID of the platform
	CallID     string `json:"call_id"`     // [-] ID of the call on the platform

	RouteID         string `json:"route_id"`         // Route's unique ID
	Socket          string `json:"socket"`           // Socket protocol to use (UDP/TCP)
	Gateway         string `json:"gateway"`          // [-] Gateway's IP and port (for Relay)
	GatewayUsername string `json:"gateway_username"` // [-] Gateway's username in the call (for P2P)

	Type      string `json:"type"`      // Connection type
	ForceTurn bool   `json:"forceturn"` // [-] Force TURN connection in P2P mode
	Peers     int    `json:"peers"`     // [-] How many peer connections to open per session

	Proto     string `json:"proto"`          // [-] Protocol to use
	Cloak     string `json:"cloak"`          // [-] Cloak method to use
	Transport string `json:"transport"`      // [-] Transport protocol to use
	Conn      string `json:"conn,omitempty"` // [-] Connection type (optional)

	PubKey     string `json:"pub_key"`    // [-] Public key of the server
	Encryption string `json:"encryption"` // Encryption mode

	Name string `json:"name"` // [-] Display name of the config

	Interactive bool `json:"-"` // [-] Allow interactive operations
}

// Validate checks that the ClientConfig contains all required fields.
func (c *ClientConfig) Validate() error {
	if common.IsNullOrWhiteSpace(c.Username) {
		return errors.New("username is required")
	}
	if common.IsNullOrWhiteSpace(c.CallID) {
		return errors.New("call_id is required")
	}
	if common.IsNullOrWhiteSpace(c.RouteID) {
		return errors.New("route_id (path) is required")
	}

	if c.Proto == "" {
		c.Proto = "none"
	}
	if c.Transport == "" {
		c.Transport = "none"
	}
	if c.Cloak == "" {
		c.Cloak = "none"
	}

	_, err := uuid.Parse(c.UserUUID)
	if err != nil {
		return fmt.Errorf("invalid user uuid: %s", c.UserUUID)
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

	switch c.Socket {
	case "tcp", "udp":
		// OK
	default:
		return fmt.Errorf("invalid socket: %s (must be tcp or udp)", c.Socket)
	}

	if c.Socket == "tcp" && c.Transport == "none" {
		return fmt.Errorf("transport is required for tcp to work reliably")
	}

	if c.Transport != "" && !common.TransportsHolder.Exists(c.Transport) {
		return fmt.Errorf("invalid transport: %s", c.Transport)
	}

	switch c.Encryption {
	case "handshake", "full":
		// OK
	default:
		return fmt.Errorf("invalid encryption mode: %s", c.Encryption)
	}

	if c.Peers <= 0 {
		return fmt.Errorf("invalid peers count: %d (must be >= 1)", c.Peers)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(c.PubKey)
	if err != nil {
		return err
	}

	_, err = mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid PQC public key structure: %w", err)
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

// NewClientConfigFromJSON creates a new ClientConfig from a config JSON
func NewClientConfigFromJSON(baseJSON string) (*ClientConfig, error) {
	var s ClientConfig
	if err := json.Unmarshal([]byte(baseJSON), &s); err != nil {
		return nil, fmt.Errorf("failed to parse client config: %w", err)
	}

	return &s, nil
}

// NewClientConfigFromURL parses a VPN connection URL into a ClientConfig.
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
		PlatformID: u.Host,
		ForceTurn:  false,
		Cloak:      "none",
		Transport:  "none",
		Proto:      "dtls",
		Conn:       "unknown",
		Peers:      1,
	}

	cfg.RouteID = strings.TrimPrefix(u.Path, "/")

	if u.User != nil {
		cfg.UserUUID = u.User.Username()
		cfg.CallID, _ = u.User.Password()
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
	if v := q.Get("socket"); v != "" {
		cfg.Socket = v
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
	if v := q.Get("transport"); v != "" {
		cfg.Transport = v
	}
	if v := q.Get("conn"); v != "" {
		cfg.Conn = v
	}
	if v := q.Get("name"); v != "" {
		cfg.Name = v
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
		cfg.Transport = "none"
	}
	if cfg.Transport == "" {
		cfg.Transport = "none"
	}
	if cfg.Cloak == "" {
		cfg.Cloak = "none"
	}

	return cfg, nil
}

// ToURL serialises the ClientConfig back into a VPN connection URL.
func (c *ClientConfig) ToURL() string {
	u := &url.URL{
		Scheme: "turnable",
		Host:   c.PlatformID,
		Path:   "/" + strings.TrimPrefix(c.RouteID, "/"),
	}

	if !common.IsNullOrWhiteSpace(c.UserUUID) || !common.IsNullOrWhiteSpace(c.CallID) {
		u.User = url.UserPassword(c.UserUUID, c.CallID)
	}

	type queryParam struct {
		key   string
		value string
	}
	params := make([]queryParam, 0, 12)

	if !common.IsNullOrWhiteSpace(c.PubKey) {
		params = append(params, queryParam{key: "pub_key", value: c.PubKey})
	}
	if !common.IsNullOrWhiteSpace(c.Username) {
		params = append(params, queryParam{key: "username", value: c.Username})
	}
	if !common.IsNullOrWhiteSpace(c.Type) {
		params = append(params, queryParam{key: "type", value: c.Type})
	}
	if !common.IsNullOrWhiteSpace(c.Encryption) {
		params = append(params, queryParam{key: "encryption", value: c.Encryption})
	}
	if !common.IsNullOrWhiteSpace(c.Transport) {
		params = append(params, queryParam{key: "transport", value: c.Transport})
	}
	if !common.IsNullOrWhiteSpace(c.Gateway) {
		params = append(params, queryParam{key: "gateway", value: c.Gateway})
	}
	if !common.IsNullOrWhiteSpace(c.Socket) {
		params = append(params, queryParam{key: "socket", value: c.Socket})
	}
	if !common.IsNullOrWhiteSpace(c.GatewayUsername) {
		params = append(params, queryParam{key: "gateway_username", value: c.GatewayUsername})
	}
	if !common.IsNullOrWhiteSpace(c.Proto) {
		params = append(params, queryParam{key: "proto", value: c.Proto})
	}
	if !common.IsNullOrWhiteSpace(c.Cloak) {
		params = append(params, queryParam{key: "cloak", value: c.Cloak})
	}
	if !common.IsNullOrWhiteSpace(c.Conn) {
		params = append(params, queryParam{key: "conn", value: c.Conn})
	}
	if !common.IsNullOrWhiteSpace(c.Name) {
		params = append(params, queryParam{key: "name", value: c.Name})
	}
	if c.ForceTurn {
		params = append(params, queryParam{key: "forceturn", value: "true"})
	}
	if c.Peers > 1 {
		params = append(params, queryParam{key: "peers", value: strconv.Itoa(c.Peers)})
	}

	if len(params) > 0 {
		var b strings.Builder
		for i, param := range params {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(param.key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(param.value))
		}
		u.RawQuery = b.String()
	}

	return u.String()
}

// ToJSON serializes this ClientConfig to JSON, optionally stripping transport-only fields
func (c *ClientConfig) ToJSON(stripped bool) (string, error) {
	if stripped {
		data := struct {
			UserUUID   string `json:"user_uuid"`
			RouteID    string `json:"route_id"`
			Socket     string `json:"socket"`
			Type       string `json:"type"`
			Encryption string `json:"encryption"`
		}{
			UserUUID:   c.UserUUID,
			RouteID:    c.RouteID,
			Socket:     c.Socket,
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
