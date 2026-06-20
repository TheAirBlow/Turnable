package relay

import (
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
)

// ClientConfig represents the relay mode client config
type ClientConfig struct {
	config.ClientConfig
	Gateway    string `json:"gateway,omitempty"  url:"query,gateway,2"`          // Gateway's IP and port
	Proto      string `json:"proto,omitempty" url:"query,proto,3"`               // Protocol to use
	Cloak      string `json:"cloak,omitempty" url:"query,cloak,4"`               // Cloak method
	Peers      int    `json:"peers,omitempty" url:"query,peers,5"`               // Peer connections per session
	Encryption string `json:"encryption,omitempty" url:"query,encryption,6"`     // Encryption mode
	PubKey     string `json:"pub_key,omitempty" url:"query,pub_key,7,omitempty"` // Public key of the server
}

// GetInner returns the inner shared configuration struct
func (c ClientConfig) GetInner() any {
	return c.ClientConfig
}

// ServerConfig represents the relay mode server config
type ServerConfig struct {
	config.ServerConfig
	Proto      string `json:"proto"`       // Protocol to use
	PubKey     string `json:"pub_key"`     // Public key
	PrivKey    string `json:"priv_key"`    // Private key
	Cloak      string `json:"cloak"`       // Cloak method to use
	PublicIP   string `json:"public_ip"`   // Server's public IP
	ListenAddr string `json:"listen_addr"` // Listening address (IP:port)
}

// GetInner returns the inner shared configuration struct
func (s ServerConfig) GetInner() any {
	return s.ServerConfig
}

// Validate validates the config
func (c ClientConfig) Validate() error {
	if c.Type != "relay" {
		return fmt.Errorf("invalid type: %s (must be relay)", c.Type)
	}

	if !common.PlatformsHolder.Exists(c.PlatformID) {
		return fmt.Errorf("invalid platform id: %s", c.PlatformID)
	}

	if !common.ConnectionsHolder.Exists(c.Type) {
		return fmt.Errorf("invalid connection type: %s", c.Type)
	}

	if !common.ProtocolsHolder.Exists(c.Proto) {
		return fmt.Errorf("invalid protocol: %s", c.Proto)
	}

	if common.IsNullOrWhiteSpace(c.CallID) {
		return errors.New("call_id is required")
	}

	if common.IsNullOrWhiteSpace(c.Gateway) {
		return errors.New("gateway is required")
	}

	if len(c.Routes) == 0 {
		return errors.New("at least one route is required")
	}

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

	if c.Peers <= 0 {
		return fmt.Errorf("invalid peers count: %d (must be >= 1)", c.Peers)
	}

	if common.IsNullOrWhiteSpace(c.Gateway) {
		return fmt.Errorf("invalid gateway: %s (must not be empty)", c.Gateway)
	}

	host, port, err := net.SplitHostPort(c.Gateway)
	if err != nil {
		return fmt.Errorf("invalid gateway: %s (expected IP:port)", c.Gateway)
	}

	if common.IsNullOrWhiteSpace(host) || common.IsNullOrWhiteSpace(port) {
		return fmt.Errorf("invalid gateway: %s (gateway IP or port is missing)", c.Gateway)
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

	return nil
}

// ToJSON serializes the config to a JSON string
func (c ClientConfig) ToJSON(indented bool, stripped bool) ([]byte, error) {
	if stripped {
		data := struct {
			UserUUID   string               `json:"user_uuid"`
			Routes     []config.ClientRoute `json:"routes"`
			Type       string               `json:"type"`
			Encryption string               `json:"encryption"`
		}{
			UserUUID:   c.UserUUID,
			Routes:     c.Routes,
			Type:       c.Type,
			Encryption: c.Encryption,
		}

		return config.ToJSON(data, indented)
	}

	return config.ToJSON(c, indented)
}

// ToURL serializes the config to a URL string
func (c ClientConfig) ToURL() (string, error) {
	return config.ToURL(c)
}

// Validate validates the config
func (s ServerConfig) Validate() error {
	if common.IsNullOrWhiteSpace(s.CallID) {
		return errors.New("call_id is required")
	}

	if common.IsNullOrWhiteSpace(s.PublicIP) {
		return errors.New("public_ip is required")
	}

	if common.IsNullOrWhiteSpace(s.ListenAddr) {
		return errors.New("listen_addr is required")
	}

	if !common.PlatformsHolder.Exists(s.PlatformID) {
		return fmt.Errorf("invalid platform id: %s", s.PlatformID)
	}

	if s.Proto == "" {
		s.Proto = "none"
	}

	if !common.ProtocolsHolder.Exists(s.Proto) {
		return fmt.Errorf("invalid protocol id: %s", s.PlatformID)
	}

	host, port, err := net.SplitHostPort(s.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen addr: %s (expected IP:port)", s.ListenAddr)
	}

	if common.IsNullOrWhiteSpace(host) || common.IsNullOrWhiteSpace(port) {
		return fmt.Errorf("invalid listen addr: %s (IP or port is missing)", s.ListenAddr)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(s.PubKey)
	if err != nil {
		return err
	}

	_, err = mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid PQC public key structure: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(s.PrivKey)
	if err != nil {
		return err
	}

	_, err = mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return fmt.Errorf("invalid PQC private key structure: %w", err)
	}

	return nil
}

// ToJSON serializes the config to a JSON string
func (s ServerConfig) ToJSON(indented bool, stripped bool) ([]byte, error) {
	if stripped {
		return nil, fmt.Errorf("stripping is not supported and isn't necessary")
	}

	return config.ToJSON(s, indented)
}

// ToURL serializes the config to a URL string
func (s ServerConfig) ToURL() (string, error) {
	return "", errors.New("URL format is not supported for server configs")
}

// GetBlankServerConfig returns a blank server config struct
func (D *Handler) GetBlankServerConfig() config.Config {
	return &ServerConfig{}
}

// GetBlankClientConfig returns a blank client config struct
func (D *Handler) GetBlankClientConfig() config.Config {
	return &ClientConfig{}
}

// GetClientConfig returns a client config for the specified user and routes
func (D *Handler) GetClientConfig(user *providers.User, routes []*providers.Route) (config.Config, error) {
	if len(routes) == 0 {
		return nil, errors.New("at least one route is required")
	}

	clientRoutes := make([]config.ClientRoute, 0, len(routes))
	names := make([]string, 0, len(routes))
	encryption := "handshake"

	for _, route := range routes {
		isAllowed := false
		for _, rID := range user.AllowedRoutes {
			if rID == route.ID {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return nil, fmt.Errorf("user %s is not authorized for route %s", user.UUID, route.ID)
		}

		trans := route.Transport
		if trans == "none" {
			trans = ""
		}

		clientRoutes = append(clientRoutes, config.ClientRoute{
			RouteID:   route.ID,
			Socket:    route.Socket,
			Transport: trans,
		})

		if route.Name != "" {
			names = append(names, route.Name)
		}
		if route.Encryption == "full" {
			encryption = "full"
		}
	}

	combinedName := strings.Join(names, ", ")
	serverCfg := D.serverConfig

	_, port, _ := net.SplitHostPort(serverCfg.ListenAddr)

	cfg := &ClientConfig{
		ClientConfig: config.ClientConfig{
			UserUUID:   user.UUID,
			Routes:     clientRoutes,
			PlatformID: serverCfg.PlatformID,
			CallID:     serverCfg.CallID,
			Type:       user.Type,
			Name:       combinedName,
		},
		PubKey:     serverCfg.PubKey,
		Peers:      max(user.Peers, 1),
		Encryption: encryption,
		Gateway:    fmt.Sprintf("%s:%s", serverCfg.PublicIP, port),
		Proto:      serverCfg.Proto,
		Cloak:      serverCfg.Cloak,
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate generated client config: %w", err)
	}

	return cfg, nil
}
