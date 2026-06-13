package config

import (
	"github.com/theairblow/turnable/pkg/common"
)

// ClientConfig represents an abstract client config
type ClientConfig struct {
	Type       string `json:"type,omitempty" url:"query,type,1"` // Connection type
	PlatformID string `json:"platform_id,omitempty" url:"host"`  // Platform's unique ID
	UserUUID   string `json:"user_uuid,omitempty" url:"user"`    // User's unique UUID
	CallID     string `json:"call_id,omitempty" url:"pass"`      // Call's ID on the platform
	Name       string `json:"name,omitempty" url:"fragment"`     // Display name
}

// ParseClientConfig parses a client config from a JSON or URL
func ParseClientConfig(raw []byte) (Config, error) {
	cfg, err := ParseConfigGeneric[ClientConfig](raw)
	if err != nil {
		return nil, err
	}

	handler, err := common.ConnectionsHolder.GetAny(cfg.Type)
	if err != nil {
		return nil, err
	}

	parser, _ := handler.(HandlerAccessor)
	target := parser.GetBlankClientConfig()
	if err := ParseConfig(raw, target); err != nil {
		return nil, err
	}

	return target, nil
}
