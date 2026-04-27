package config

import (
	"encoding/json"

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
	GetAllRoutes() []Route               // Fetches all available routes
	Stop() error                         // Stops the provider connection
}

// Providers represents a Provider registry
var Providers = common.NewRegistry[Provider]()

// init registers all available route and user providers
func init() {
	common.ProvidersHolder = Providers
	Providers.Register(&RawProvider{})
	Providers.Register(&JSONProvider{})
}

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
