package main

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/config"
)

// configGenerateOptions holds CLI flags for the config generate subcommand
type configGenerateOptions struct {
	configPath string
	routeID    string
	userUUID   string
	json       bool
}

// configKeygenOptions holds CLI flags for the config keygen subcommand
type configKeygenOptions struct {
	json bool
}

// configDirectOptions holds CLI flags for the direct relay config subcommand
type configDirectOptions struct {
	platformId string
	callId     string
	username   string
	gateway    string
	peers      int
	json       bool
}

// newConfigCommand creates the config cobra command
func newConfigCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "config",
		Short: "Config generation and management utilities",
	}

	root.AddCommand(newConfigGenerateCommand())
	root.AddCommand(newConfigKeygenCommand())
	root.AddCommand(newConfigDirectCommand())
	return root
}

// newConfigGenerateCommand creates the generate config cobra command
func newConfigGenerateCommand() *cobra.Command {
	opts := &configGenerateOptions{}

	cmd := &cobra.Command{
		Use:   "generate <route-id> <user-uuid>",
		Short: "Generates a client config from server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("expected exactly 2 positional arguments")
			}
			opts.routeID = args[0]
			opts.userUUID = args[1]
			return configMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "config.json", "server config JSON file path")
	cmd.Flags().BoolVarP(&opts.json, "json", "j", false, "output config in json format")
	return cmd
}

// newConfigKeygenCommand creates the config keygen cobra command
func newConfigKeygenCommand() *cobra.Command {
	opts := &configKeygenOptions{}

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate ML-KEM-768 keys for config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return keygenMain(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.json, "json", false, "print keys as a JSON object")
	return cmd
}

// newConfigDirectCommand creates the direct relay config cobra command
func newConfigDirectCommand() *cobra.Command {
	opts := &configDirectOptions{}

	cmd := &cobra.Command{
		Use:   "direct <platform-id> <call-id> <username> <gateway-addr>",
		Short: "Generates a direct relay connection client config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 4 {
				return errors.New("expected exactly 4 positional arguments")
			}
			opts.platformId = args[0]
			opts.callId = args[1]
			opts.username = args[2]
			opts.gateway = args[3]
			return directConfigMain(opts)
		},
	}

	cmd.Flags().IntVarP(&opts.peers, "peers", "n", 1, "how many peer connections to use")
	cmd.Flags().BoolVarP(&opts.json, "json", "j", false, "output config in json format")
	return cmd
}

// configMain runs the config command
func configMain(opts *configGenerateOptions) error {
	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config json file: %w", err)
	}

	serverCfg, err := config.NewServerConfigFromJSON(string(configData))
	if err != nil {
		return fmt.Errorf("failed to parse config json file: %w", err)
	}
	if err := serverCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate server config: %w", err)
	}

	if err := serverCfg.UpdateProvider(); err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	user, err := serverCfg.GetUser(opts.userUUID)
	if err != nil {
		return fmt.Errorf("failed to resolve user: %w", err)
	}

	route, err := serverCfg.GetRoute(opts.routeID)
	if err != nil {
		return fmt.Errorf("failed to resolve route: %w", err)
	}

	clientCfg, err := serverCfg.GetClientConfig(user, route)
	if err != nil {
		return fmt.Errorf("failed to generate client config: %w", err)
	}

	if err := clientCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate client config: %w", err)
	}

	if opts.json {
		fmt.Println(clientCfg.ToJSON(false))
	} else {
		fmt.Println(clientCfg.ToURL())
	}

	return nil
}

// serverMain runs the keygen command
func keygenMain(opts *configKeygenOptions) error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}

	priv := base64.StdEncoding.EncodeToString(dk.Bytes())
	pub := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	if opts.json {
		payload := map[string]string{
			"priv_key": priv,
			"pub_key":  pub,
		}
		out, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("priv_key=%s\n", priv)
	fmt.Printf("pub_key=%s\n", pub)
	return nil
}

// directConfigMain runs the direct relay config command
func directConfigMain(opts *configDirectOptions) error {
	clientCfg := config.ClientConfig{
		UserUUID:   "INSECURE-DIRECT-RELAY",
		PlatformID: opts.platformId,
		CallID:     opts.callId,
		Username:   opts.username,
		Gateway:    opts.gateway,
		Peers:      opts.peers,
		Socket:     "udp",
		Type:       "direct",
		Proto:      "none",
	}

	if err := clientCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate client config: %w", err)
	}

	if opts.json {
		fmt.Println(clientCfg.ToJSON(false))
	} else {
		fmt.Println(clientCfg.ToURL())
	}

	return nil
}
