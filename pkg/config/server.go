package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config/providers"
)

// ServersConfig represents the configs of all servers and provides easy access to users and routes
type ServersConfig struct {
	Servers   map[string]json.RawMessage `json:"servers"`   // Named list of servers to run
	Providers map[string]json.RawMessage `json:"providers"` // Named list of all providers
}

// ServerConfig represents an abstract server config
type ServerConfig struct {
	Type       string `json:"type"`        // Connection type
	Provider   string `json:"provider"`    // Provider ID
	PlatformID string `json:"platform_id"` // ID of the platform
	CallID     string `json:"call_id"`     // ID of the call on the platform
}

// ProviderConfig represents provider configuration options
type ProviderConfig struct {
	Type string `json:"type"` // Provider type
}

// ParseServersConfig parses the servers config JSON and initializes providers
func ParseServersConfig(raw []byte) (ServersConfig, error) {
	var target ServersConfig
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return target, fmt.Errorf("empty configuration string")
	}

	if err := json.Unmarshal(raw, &target); err != nil {
		return target, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return target, nil
}

// ParseServerConfig parses a server config from a JSON or URL
func ParseServerConfig(raw []byte) (Config, error) {
	cfg, err := ParseConfigGeneric[ServerConfig](raw)
	if err != nil {
		return nil, err
	}

	handler, err := common.ConnectionsHolder.GetAny(cfg.Type)
	if err != nil {
		return nil, err
	}

	parser, _ := handler.(HandlerAccessor)
	target := parser.GetBlankServerConfig()
	if target == nil {
		return nil, fmt.Errorf("connection type %s doesn't support server mode", cfg.Type)
	}

	if err := ParseConfig(raw, target); err != nil {
		return nil, err
	}

	return target, nil
}

// GetServerConfig parses the server config for specified server ID
func (s *ServersConfig) GetServerConfig(id string) (Config, error) {
	raw, ok := s.Servers[id]
	if !ok {
		return nil, fmt.Errorf("server '%s' not found", id)
	}

	return ParseServerConfig(raw)
}

// GetProvider parses the provider config for specified provider ID and returns a provider instance without initializing it
func (s *ServersConfig) GetProvider(id string) (providers.Provider, error) {
	raw, ok := s.Providers[id]
	if !ok {
		return nil, fmt.Errorf("provider '%s' not found", id)
	}

	cfg, err := ParseConfigGeneric[ProviderConfig](raw)
	if err != nil {
		return nil, err
	}

	handler, err := common.ProvidersHolder.GetAny(cfg.Type)
	if err != nil {
		return nil, err
	}

	provider, _ := handler.(providers.Provider)
	return provider, nil
}
