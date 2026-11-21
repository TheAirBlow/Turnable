package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/theairblow/turnable/pkg/common"
)

// ClientConfig represents an abstract client config
type ClientConfig struct {
	Type       string        `json:"type,omitempty" url:"query,type,1"`             // Connection type
	PlatformID string        `json:"platform_id,omitempty" url:"host"`              // Platform's unique ID
	UserUUID   string        `json:"user_uuid,omitempty" url:"user"`                // User's unique UUID
	CallID     string        `json:"call_id,omitempty" url:"pass"`                  // Call's ID on the platform
	Routes     []ClientRoute `json:"routes,omitempty" url:"path"`                   // Ordered list of tunnel routes
	Name       string        `json:"name,omitempty" url:"fragment"`                 // Display name
	Ports      string        `json:"ports,omitempty" url:"query,ports,8,omitempty"` // Suggested local ports, comma-separated in route order
}

// SuggestedPort returns the local port the config suggests for route i, or 0 when it suggests none
func (c ClientConfig) SuggestedPort(i int) int {
	if c.Ports == "" {
		return 0
	}

	parts := strings.Split(c.Ports, ",")
	if i >= len(parts) {
		return 0
	}

	n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
	if err != nil || n < 1 || n > 65535 {
		return 0
	}

	return n
}

// ValidatePorts checks that ports holds at most one entry per route, each empty, 0 or a valid port
func (c ClientConfig) ValidatePorts() error {
	if c.Ports == "" {
		return nil
	}

	parts := strings.Split(c.Ports, ",")
	if len(parts) > len(c.Routes) {
		return fmt.Errorf("ports has %d entries but there are only %d routes", len(parts), len(c.Routes))
	}

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("ports[%d]: invalid port %q", i, part)
		}
	}

	return nil
}

// ClientRoute represents one tunnel route inside a multi-route client config
type ClientRoute struct {
	RouteID   string `json:"route_id" url:"path,1"`            // Route's unique ID
	Socket    string `json:"socket" url:"path,2"`              // Socket protocol to use
	Transport string `json:"transport,omitempty" url:"path,3"` // Transport protocol to use
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
