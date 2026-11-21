package config

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ServiceConfig represents the service server configuration JSON
type ServiceConfig struct {
	UnixSocket string `json:"unix_socket,omitempty"` // Unix socket file to listen on
	ListenAddr string `json:"listen_addr,omitempty"` // TCP address and port to listen on

	PubKey  string `json:"pub_key,omitempty"`  // Public key
	PrivKey string `json:"priv_key,omitempty"` // Private key

	AllowedKeys  []string `json:"allowed_keys,omitempty"`  // Client public keys with full access
	ReadonlyKeys []string `json:"readonly_keys,omitempty"` // Client public keys that may only read

	PersistDir string `json:"persist_dir,omitempty"` // Instance config persistence directory
}

// NewServiceConfigFromJSON creates a new ServiceConfig from a JSON
func NewServiceConfigFromJSON(baseJSON string) (*ServiceConfig, error) {
	var s ServiceConfig
	if err := json.Unmarshal([]byte(baseJSON), &s); err != nil {
		return nil, fmt.Errorf("failed to parse base server config: %w", err)
	}

	return &s, nil
}

// Validate validates the ServiceConfig
func (s *ServiceConfig) Validate() error {
	if s.UnixSocket == "" && s.ListenAddr == "" {
		return fmt.Errorf("either unix_socket, listen_addr, or both must be set")
	}

	if len(s.AllowedKeys) != 0 || len(s.ReadonlyKeys) != 0 || s.PubKey != "" || s.PrivKey != "" {
		pubBytes, err := base64.StdEncoding.DecodeString(s.PubKey)
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}

		_, err = mlkem.NewEncapsulationKey768(pubBytes)
		if err != nil {
			return fmt.Errorf("invalid PQC public key structure: %w", err)
		}

		privBytes, err := base64.StdEncoding.DecodeString(s.PrivKey)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}

		_, err = mlkem.NewDecapsulationKey768(privBytes)
		if err != nil {
			return fmt.Errorf("invalid PQC private key structure: %w", err)
		}
	}

	for name, keys := range map[string][]string{"allowed_keys": s.AllowedKeys, "readonly_keys": s.ReadonlyKeys} {
		for i, k := range keys {
			kb, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				return fmt.Errorf("%s[%d] is not valid base64: %w", name, i, err)
			}

			if _, err := mlkem.NewEncapsulationKey768(kb); err != nil {
				return fmt.Errorf("%s[%d] is not a valid PQC public key: %w", name, i, err)
			}
		}
	}

	return nil
}

// ToJSON serializes this ServiceConfig to a JSON file
func (s *ServiceConfig) ToJSON(indented bool) ([]byte, error) {
	var b []byte
	var err error

	if indented {
		b, err = json.MarshalIndent(s, "", "    ")
	} else {
		b, err = json.Marshal(s)
	}

	if err != nil {
		return nil, err
	}

	return b, nil
}
