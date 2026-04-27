package config

import (
	"encoding/json"
	"fmt"
	"sync"
)

// RawProvider represents a Provider from raw provider config JSON
type RawProvider struct {
	mu sync.RWMutex

	data struct {
		Routes map[string]Route `json:"routes"`
		Users  map[string]User  `json:"users"`
	}
}

// ID returns the unique ID of this provider
func (j *RawProvider) ID() string {
	return "raw"
}

// Update updates or initializes provider configuration
func (j *RawProvider) Update(config json.RawMessage) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	var newData struct {
		Routes []Route `json:"routes"`
		Users  []User  `json:"users"`
	}

	if err := json.Unmarshal(config, &newData); err != nil {
		return fmt.Errorf("failed to parse provider JSON: %w", err)
	}

	routes := make(map[string]Route, len(newData.Routes))
	for _, route := range newData.Routes {
		if route.ID == "" {
			return fmt.Errorf("failed to parse provider JSON: routes[].id is required")
		}
		if _, exists := routes[route.ID]; exists {
			return fmt.Errorf("failed to parse provider JSON: duplicate route id %q", route.ID)
		}
		routes[route.ID] = route
	}

	users := make(map[string]User, len(newData.Users))
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

// ToJSON serializes provider config to config JSON
func (j *RawProvider) ToJSON() (json.RawMessage, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	data := struct {
		Routes []Route `json:"routes"`
		Users  []User  `json:"users"`
	}{
		Routes: make([]Route, 0, len(j.data.Routes)),
		Users:  make([]User, 0, len(j.data.Users)),
	}

	for _, r := range j.data.Routes {
		data.Routes = append(data.Routes, r)
	}

	for _, u := range j.data.Users {
		data.Users = append(data.Users, u)
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal provider data: %w", err)
	}

	return jsonBytes, nil
}

// GetRoute fetches a Route based on its ID
func (j *RawProvider) GetRoute(id string) (*Route, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	route, ok := j.data.Routes[id]
	if !ok {
		return nil, fmt.Errorf("route '%s' not found", id)
	}

	return &route, nil
}

// GetUser fetches a User based on their UUID
func (j *RawProvider) GetUser(uuid string) (*User, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	user, ok := j.data.Users[uuid]
	if !ok {
		return nil, fmt.Errorf("user '%s' not found", uuid)
	}

	return &user, nil
}

// GetAllRoutes fetches all available routes
func (j *RawProvider) GetAllRoutes() []Route {
	j.mu.RLock()
	defer j.mu.RUnlock()

	routes := make([]Route, 0, len(j.data.Routes))
	for _, r := range j.data.Routes {
		routes = append(routes, r)
	}
	return routes
}

// AddRoute adds or updates a route
func (j *RawProvider) AddRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}

	if route.ID == "" {
		return fmt.Errorf("route id is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.data.Routes[route.ID] = *route
	return nil
}

// AddUser adds or updates a user
func (j *RawProvider) AddUser(user *User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if user.UUID == "" {
		return fmt.Errorf("user uuid is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.data.Users[user.UUID] = *user
	return nil
}

// Stop stops the provider connection
func (j *RawProvider) Stop() error {
	return nil
}
