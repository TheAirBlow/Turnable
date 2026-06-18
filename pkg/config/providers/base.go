package providers

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/theairblow/turnable/pkg/common"
)

// Provider represents a Route and User provider
type Provider interface {
	ID() string                          // Returns the unique ID of this provider
	Update(config json.RawMessage) error // Updates or initializes provider configuration
	ToJSON() (json.RawMessage, error)    // Serializes provider config to config JSON
	GetRoute(id string) (*Route, error)  // Fetches a Route based on its ID
	GetUser(uuid string) (*User, error)  // Fetches a User based on their UUID
	AddRoute(route *Route) error         // Adds or updates a route
	AddUser(user *User) error            // Adds or updates a user
	DeleteRoute(id string) error         // Removes a route by ID
	DeleteUser(uuid string) error        // Removes a user by UUID
	GetAllRoutes() []Route               // Fetches all available routes
	GetAllUsers() []User                 // Fetches all available users
	Stop() error                         // Stops the provider connection
}

// User represents a VPN user
type User struct {
	UUID          string   `json:"uuid"`           // Unique UUID of this user
	AllowedRoutes []string `json:"allowed_routes"` // Allowed route IDs

	Type      string `json:"type"`                // Connection type
	ForceTurn bool   `json:"forceturn,omitempty"` // Force TURN in P2P mode
	Peers     int    `json:"peers"`               // Peer connections per session
}

// Route represents a tunnel route
type Route struct {
	ID string `json:"id"` // Unique ID of this route

	Address   string `json:"address"`             // IP address of the destination server
	Port      int    `json:"port"`                // Port of the destination server
	Socket    string `json:"socket"`              // Socket protocol to use
	Transport string `json:"transport,omitempty"` // Transport protocol to use

	Encryption string `json:"encryption"` // Encryption mode
	Name       string `json:"name"`       // Display name shown in generated client configs
}

// Validate validates the Route
func (r *Route) Validate() error {
	switch r.Socket {
	case "tcp", "udp":
		// OK
	default:
		return fmt.Errorf("route %q has invalid socket type %q (must be tcp or udp)", r.ID, r.Socket)
	}

	if r.Transport == "" {
		r.Transport = "none"
	}

	if r.Transport != "" && !common.TransportsHolder.Exists(r.Transport) {
		return fmt.Errorf("route %q has invalid transport: %s", r.ID, r.Transport)
	}

	if r.Socket == "tcp" && r.Transport == "none" {
		return fmt.Errorf("transport is required for tcp to work reliably")
	}

	if net.ParseIP(r.Address) == nil {
		return fmt.Errorf("invalid address: %s", r.Address)
	}

	switch r.Encryption {
	case "handshake", "full":
		// OK
	case "":
		r.Encryption = "handshake"
	default:
		return fmt.Errorf("route %q has invalid encryption mode: %s", r.ID, r.Encryption)
	}

	return nil
}

// Providers represents a Provider registry
var Providers = common.NewRegistry[Provider]()

// GetProvider fetches a Provider by its string ID
func GetProvider(name string) (Provider, error) {
	return Providers.Get(name)
}

// ListProviders lists all Provider string IDs
func ListProviders() []string {
	return Providers.List()
}

// ProviderExists checks whether a Provider with specified string ID exists
func ProviderExists(name string) bool {
	return Providers.Exists(name)
}
