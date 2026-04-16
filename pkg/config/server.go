package config

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/theairblow/turnable/pkg/common"
)

// ServerConfig represents the server configuration JSON and provides easy access to users and routes
type ServerConfig struct {
	PlatformID string `json:"platform_id"` // ID of the platform
	CallID     string `json:"call_id"`     // ID of the call on the platform

	PubKey  string `json:"pub_key"`  // Public key
	PrivKey string `json:"priv_key"` // Private key

	Relay RelayServerConfig `json:"relay"`
	P2P   P2PServerConfig   `json:"p2p"`

	provider Provider // User and Route provider
}

// User represents a VPN user
type User struct {
	UUID          string   `json:"uuid"`           // Unique UUID of this user
	AllowedRoutes []string `json:"allowed_routes"` // Allowed route IDs
}

// RelayServerConfig provides relay mode server configuration
type RelayServerConfig struct {
	Enabled  bool   `json:"enabled"`        // Whether relay server is enabled or not
	Proto    string `json:"proto"`          // Socket to use
	Cloak    string `json:"cloak"`          // Cloak method to use
	PublicIP string `json:"public_ip"`      // Server's public IP
	Port     *int   `json:"port,omitempty"` // UDP port to listen on
}

// P2PServerConfig provides P2P mode server configuration
type P2PServerConfig struct {
	Enabled  bool   `json:"enabled"`  // Whether P2P server is enabled or not
	Username string `json:"username"` // Username to use in the call
	Cloak    string `json:"cloak"`    // Cloak method to use
}

// Route represents a tunnel route
type Route struct {
	ID string `json:"id"` // Unique ID of this route

	Address   string `json:"address"`             // IP address of the destination server
	Port      int    `json:"port"`                // Port of the destination server
	Socket    string `json:"socket"`              // Socket protocol to use (UDP/TCP)
	Transport string `json:"transport,omitempty"` // Transport protocol to use (none/sctp/kcp)

	Conn string `json:"conn,omitempty"` // Connection type (optional)

	ClientPrefs ClientPrefs `json:"client_prefs"` // Client config preferences
}

// ClientPrefs provides extra parameters required to generate a ClientConfig
type ClientPrefs struct {
	Username string `json:"username"` // Username to use in the call

	Type      string `json:"type"`      // Connection type
	ForceTurn bool   `json:"forceturn"` // Force TURN connection in P2P mode
	Peers     int    `json:"peers"`     // How many peer connections to open per session

	Encryption string `json:"encryption"` // Encryption mode

	Name string `json:"name"` // Display name of the config
}

// Provider represents a Route and User provider
type Provider interface {
	GetRoute(id string) (*Route, error)
	GetUser(uuid string) (*User, error)
	GetAllRoutes() []Route
}

// NewServerConfigFromJSON creates a new ServerConfig from a base config JSON and Provider
func NewServerConfigFromJSON(baseJSON string, p Provider) (*ServerConfig, error) {
	var s ServerConfig
	if err := json.Unmarshal([]byte(baseJSON), &s); err != nil {
		return nil, fmt.Errorf("failed to parse base server config: %w", err)
	}

	s.provider = p
	return &s, nil
}

// Validate validates the ServerConfig
func (s *ServerConfig) Validate() error {
	if s.provider == nil {
		return errors.New("config provider must be initialized")
	}
	if common.IsNullOrWhiteSpace(s.CallID) {
		return errors.New("call_id is required")
	}
	if !s.Relay.Enabled && !s.P2P.Enabled {
		return errors.New("at least one server mode must be enabled")
	}

	if !common.PlatformsHolder.Exists(s.PlatformID) {
		return fmt.Errorf("invalid platform id: %s", s.PlatformID)
	}

	if !common.IsNullOrWhiteSpace(s.Relay.PublicIP) {
		host, _, err := net.SplitHostPort(s.Relay.PublicIP)
		if err != nil {
			if net.ParseIP(s.Relay.PublicIP) == nil {
				return fmt.Errorf("invalid relay public_ip format: %s", s.Relay.PublicIP)
			}
		} else if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid host in relay public_ip: %s", host)
		}
	}

	for _, route := range s.GetAllRoutes() {
		err := route.Validate()
		if err != nil {
			return common.WrapError(fmt.Sprintf("route %s is invalid", route.ID), err)
		}
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

// Validate validates the Route
func (r *Route) Validate() error {
	switch r.Socket {
	case "tcp", "udp":
		// OK
	default:
		return fmt.Errorf("route %q has invalid socket type %q (must be tcp or udp)", r.ID, r.Socket)
	}

	if r.Transport == "none" {
		r.Transport = ""
	}

	if r.Transport != "" && !common.TransportsHolder.Exists(r.Transport) {
		return fmt.Errorf("route %q has invalid transport: %s", r.ID, r.Transport)
	}

	if net.ParseIP(r.Address) == nil {
		return fmt.Errorf("invalid address: %s", r.Address)
	}

	if !common.ConnectionsHolder.Exists(r.ClientPrefs.Type) {
		return fmt.Errorf("invalid connection type: %s", r.ClientPrefs.Type)
	}

	switch r.ClientPrefs.Encryption {
	case "handshake", "full":
		// OK
	default:
		return fmt.Errorf("invalid encryption mode: %s", r.ClientPrefs.Encryption)
	}

	if r.ClientPrefs.Peers <= 0 {
		return fmt.Errorf("invalid peers count: %d (must be >= 1)", r.ClientPrefs.Peers)
	}

	return nil
}

// GetClientConfig generates a ClientConfig for the specified User and Route
func (s *ServerConfig) GetClientConfig(user *User, route *Route) (*ClientConfig, error) {
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

	p := route.ClientPrefs
	cfg := &ClientConfig{
		// From User Identity
		UserUUID: user.UUID,
		Username: p.Username,

		// From Global Init
		PlatformID: s.PlatformID,
		CallID:     s.CallID,
		PubKey:     s.PubKey,

		// From Route Identity
		RouteID: route.ID,
		Socket:  route.Socket,
		Conn:    route.Conn,

		// From Client Prefs
		Type:       p.Type,
		ForceTurn:  p.ForceTurn,
		Peers:      max(p.Peers, 1),
		Transport:  route.Transport,
		Encryption: p.Encryption,
		Name:       p.Name,
	}

	if s.Relay.Enabled {
		cfg.Gateway = fmt.Sprintf("%s:%d", s.Relay.PublicIP, *s.Relay.Port)
		cfg.Proto = s.Relay.Proto
		cfg.Cloak = s.Relay.Cloak
	}

	if s.P2P.Enabled {
		cfg.GatewayUsername = s.P2P.Username
		cfg.Cloak = s.P2P.Cloak
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated client config is invalid: %w", err)
	}

	return cfg, nil
}

// GetRoute fetches a Route based on it's ID
func (s *ServerConfig) GetRoute(id string) (*Route, error) {
	if s.provider == nil {
		return nil, fmt.Errorf("no config provider initialized")
	}
	return s.provider.GetRoute(id)
}

// GetUser fetches a User based on it's UUID
func (s *ServerConfig) GetUser(uuid string) (*User, error) {
	if s.provider == nil {
		return nil, fmt.Errorf("no config provider initialized")
	}
	return s.provider.GetUser(uuid)
}

// GetAllRoutes fetches all available routes
func (s *ServerConfig) GetAllRoutes() []Route {
	if s.provider == nil {
		return nil
	}
	return s.provider.GetAllRoutes()
}

// ToJSON serializes this ServerConfig to a JSON file
func (s *ServerConfig) ToJSON() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
