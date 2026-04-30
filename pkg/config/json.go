package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// JSONProvider represents a Provider from a JSON file
type JSONProvider struct {
	mu sync.RWMutex

	path string // resolved path to the backing JSON file

	data struct {
		Routes map[string]Route `json:"routes"`
		Users  map[string]User  `json:"users"`
	}
}

// JSONProviderConfig represents JSONProvider configuration
type JSONProviderConfig struct {
	Path string `json:"path"` // Path to JSON file
}

// ID returns the unique ID of this provider
func (j *JSONProvider) ID() string {
	return "json"
}

// Update updates or initializes provider configuration
func (j *JSONProvider) Update(config json.RawMessage) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	var cfg JSONProviderConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("failed to parse JSON provider config: %w", err)
	}

	storeData, err := os.ReadFile(cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to read store json file: %w", err)
	}

	var newData struct {
		Routes []Route `json:"routes"`
		Users  []User  `json:"users"`
	}

	if err := json.Unmarshal(storeData, &newData); err != nil {
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

	for _, route := range routes {
		err := route.Validate()
		if err != nil {
			return fmt.Errorf("route %s is invalid: %w", route.ID, err)
		}
	}

	j.data.Routes = routes
	j.data.Users = users
	j.path = cfg.Path
	return nil
}

// ToJSON serializes provider config to config JSON
func (j *JSONProvider) ToJSON() (json.RawMessage, error) {
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
func (j *JSONProvider) GetRoute(id string) (*Route, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	route, ok := j.data.Routes[id]
	if !ok {
		return nil, fmt.Errorf("route '%s' not found", id)
	}

	return &route, nil
}

// GetUser fetches a User based on their UUID
func (j *JSONProvider) GetUser(uuid string) (*User, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	user, ok := j.data.Users[uuid]
	if !ok {
		return nil, fmt.Errorf("user '%s' not found", uuid)
	}

	return &user, nil
}

// GetAllRoutes fetches all available routes
func (j *JSONProvider) GetAllRoutes() []Route {
	j.mu.RLock()
	defer j.mu.RUnlock()

	routes := make([]Route, 0, len(j.data.Routes))
	for _, r := range j.data.Routes {
		routes = append(routes, r)
	}
	return routes
}

// saveToDiskLocked serializes the current data and writes it to the backing JSON file
func (j *JSONProvider) saveToDiskLocked() error {
	if j.path == "" {
		return fmt.Errorf("json provider path not set")
	}

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

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json provider data: %w", err)
	}

	if err := os.WriteFile(j.path, b, 0o640); err != nil {
		return fmt.Errorf("write json provider file: %w", err)
	}

	return nil
}

// AddRoute adds or updates a route
func (j *JSONProvider) AddRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}

	if route.ID == "" {
		return fmt.Errorf("route id is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.data.Routes[route.ID] = *route
	return j.saveToDiskLocked()
}

// AddUser adds or updates a user
func (j *JSONProvider) AddUser(user *User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if user.UUID == "" {
		return fmt.Errorf("user uuid is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.data.Users[user.UUID] = *user
	return j.saveToDiskLocked()
}

// DeleteRoute removes a route by ID
func (j *JSONProvider) DeleteRoute(id string) error {
	if id == "" {
		return fmt.Errorf("route id is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if _, ok := j.data.Routes[id]; !ok {
		return fmt.Errorf("route '%s' not found", id)
	}

	delete(j.data.Routes, id)
	return j.saveToDiskLocked()
}

// DeleteUser removes a user by UUID
func (j *JSONProvider) DeleteUser(uuid string) error {
	if uuid == "" {
		return fmt.Errorf("user uuid is required")
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if _, ok := j.data.Users[uuid]; !ok {
		return fmt.Errorf("user '%s' not found", uuid)
	}

	delete(j.data.Users, uuid)
	return j.saveToDiskLocked()
}

// Stop stops the provider connection
func (j *JSONProvider) Stop() error {
	return nil
}
