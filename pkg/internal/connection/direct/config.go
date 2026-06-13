package direct

import (
	"errors"
	"fmt"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
)

// ClientConfig represents the direct mode client config
type ClientConfig struct {
	config.ClientConfig
	Gateway string `json:"gateway"  url:"query,gateway,2"` // Gateway's IP and port
	Peers   int    `json:"peers" url:"query,peers,3"`      // Peer connections per session
}

// Validate validates the config
func (c ClientConfig) Validate() error {
	if c.Type != "direct" {
		return fmt.Errorf("invalid type: %s (must be direct)", c.Type)
	}

	if !common.PlatformsHolder.Exists(c.PlatformID) {
		return fmt.Errorf("invalid platform id: %s", c.PlatformID)
	}

	if common.IsNullOrWhiteSpace(c.CallID) {
		return errors.New("call_id is required")
	}

	if common.IsNullOrWhiteSpace(c.Gateway) {
		return errors.New("gateway is required")
	}

	if c.UserUUID != "INSECURE-DIRECT-RELAY" {
		return fmt.Errorf("invalid user UUID: %s (must be INSECURE-DIRECT-RELAY)", c.UserUUID)
	}

	if c.Peers <= 0 {
		return fmt.Errorf("invalid peers count: %d (must be >= 1)", c.Peers)
	}

	host, port, err := net.SplitHostPort(c.Gateway)
	if err != nil {
		return fmt.Errorf("invalid gateway: %s (expected IP:port)", c.Gateway)
	}

	if common.IsNullOrWhiteSpace(host) || common.IsNullOrWhiteSpace(port) {
		return fmt.Errorf("invalid gateway: %s (IP or port is missing)", c.Gateway)
	}

	return nil
}

// ToJSON serializes the config to a JSON string
func (c ClientConfig) ToJSON(indented bool, stripped bool) ([]byte, error) {
	if stripped {
		return nil, fmt.Errorf("stripping is not supported and isn't necessary")
	}

	return config.ToJSON(c, indented)
}

// ToURL serializes the config to a URL string
func (c ClientConfig) ToURL() (string, error) {
	return config.ToURL(c)
}

// GetBlankServerConfig returns a blank server config struct
func (D *Handler) GetBlankServerConfig() config.Config {
	return nil
}

// GetBlankClientConfig returns a blank client config struct
func (D *Handler) GetBlankClientConfig() config.Config {
	return &ClientConfig{}
}

// GetClientConfig returns a client config for the specified user and routes
func (D *Handler) GetClientConfig(_ *providers.User, _ []*providers.Route) (*config.Config, error) {
	return nil, errors.New("direct handler does not support server mode")
}
