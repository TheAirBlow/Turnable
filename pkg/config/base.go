package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/theairblow/turnable/pkg/common"
)

// Config represents a config that can be validated and serialized
type Config interface {
	Validate() error                                     // Validates the config
	ToJSON(indented bool, stripped bool) ([]byte, error) // Serializes the config to a JSON string
	ToURL() (string, error)                              // Serializes the config to a URL string
	GetInner() any                                       // Returns the inner shared configuration struct
}

// HandlerAccessor represents a connection handler accessor (hacky as fuck but works)
type HandlerAccessor interface {
	GetBlankServerConfig() Config // Returns a blank server config struct
	GetBlankClientConfig() Config // Returns a blank client config struct
}

// URL schema for Turnable
const urlSchema = "turnable"

// ToJSON serializes any configuration struct to a JSON string
func ToJSON(cfg any, indented bool) ([]byte, error) {
	var out []byte
	var err error

	if indented {
		out, err = json.MarshalIndent(cfg, "", "    ")
	} else {
		out, err = json.Marshal(cfg)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to serialize to JSON: %w", err)
	}

	return out, nil
}

// ToURL serializes any configuration struct to a URL string
func ToURL(cfg any) (string, error) {
	urlStr, err := common.MarshalURL(cfg, urlSchema)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to URL: %w", err)
	}

	return urlStr, nil
}

// ParseConfigGeneric parses a server config from a JSON or URL
func ParseConfigGeneric[T any](raw []byte) (T, error) {
	var target T
	if err := ParseConfig(raw, &target); err != nil {
		return target, err
	}

	return target, nil
}

// ParseConfig parses a server config from a JSON or URL
func ParseConfig(raw []byte, v any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return fmt.Errorf("empty configuration string")
	}

	if bytes.HasPrefix(raw, []byte("{")) {
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		if err := common.UnmarshalURL(string(raw), urlSchema, &v); err != nil {
			return fmt.Errorf("failed to parse URL: %w", err)
		}
	}

	return nil
}
