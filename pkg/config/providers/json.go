package providers

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/theairblow/turnable/pkg/config"
)

// JSONProvider represents a Route and User provider from a JSON object
type JSONProvider struct {
	mu sync.RWMutex

	data struct {
		Routes map[string]config.Route `json:"routes"`
		Users  map[string]config.User  `json:"users"`
	}
}

// NewJSONProviderFromJSON creates a new JSONProvider from a JSON object
func NewJSONProviderFromJSON(jsonStr string) (*JSONProvider, error) {
	p := &JSONProvider{}
	p.data.Routes = make(map[string]config.Route)
	p.data.Users = make(map[string]config.User)
	err := p.UpdateFromJSON(jsonStr)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdateFromJSON updates the data store from the supplied JSON object
func (j *JSONProvider) UpdateFromJSON(jsonStr string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	var newData struct {
		Routes []config.Route `json:"routes"`
		Users  []config.User  `json:"users"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &newData); err != nil {
		return fmt.Errorf("failed to parse provider JSON: %w", err)
	}

	routes := make(map[string]config.Route, len(newData.Routes))
	for _, route := range newData.Routes {
		if route.ID == "" {
			return fmt.Errorf("failed to parse provider JSON: routes[].id is required")
		}
		if _, exists := routes[route.ID]; exists {
			return fmt.Errorf("failed to parse provider JSON: duplicate route id %q", route.ID)
		}
		routes[route.ID] = route
	}

	users := make(map[string]config.User, len(newData.Users))
	for _, user := range newData.Users {
		if user.UUID == "" {
			return fmt.Errorf("failed to parse provider JSON: users[].uuid is required")
		}
		if _, exists := users[user.UUID]; exists {
			return fmt.Errorf("failed to parse provider JSON: duplicate user uuid %q", user.UUID)
		}
		users[user.UUID] = user
	}

	j.data.Routes = routes
	j.data.Users = users
	return nil
}

// GetRoute fetches a Route based on it's ID
func (j *JSONProvider) GetRoute(id string) (*config.Route, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	route, ok := j.data.Routes[id]
	if !ok {
		return nil, fmt.Errorf("route '%s' not found", id)
	}

	return &route, nil
}

// GetUser fetches a User based on it's UUID
func (j *JSONProvider) GetUser(uuid string) (*config.User, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	user, ok := j.data.Users[uuid]
	if !ok {
		return nil, fmt.Errorf("user '%s' not found", uuid)
	}

	return &user, nil
}

// GetAllRoutes fetches all available routes
func (j *JSONProvider) GetAllRoutes() []config.Route {
	j.mu.RLock()
	defer j.mu.RUnlock()

	routes := make([]config.Route, 0, len(j.data.Routes))
	for _, r := range j.data.Routes {
		routes = append(routes, r)
	}
	return routes
}
