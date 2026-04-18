package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	configpkg "github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
)

// configOptions holds CLI flags for the config subcommand
type configOptions struct {
	configPath string
	storePath  string
	routeID    string
	userUUID   string
}

// newConfigCommand creates the config cobra command
func newConfigCommand() *cobra.Command {
	opts := &configOptions{}

	cmd := &cobra.Command{
		Use:   "config <route-id> <user-uuid>",
		Short: "Generate a client config URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("expected exactly two positional arguments: <route-id> <user-uuid>")
			}
			opts.routeID = args[0]
			opts.userUUID = args[1]
			return configMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "config.json", "server config JSON file path")
	cmd.Flags().StringVarP(&opts.storePath, "store", "s", "store.json", "server user/route store JSON file path")
	return cmd
}

// serverMain runs the config command
func configMain(opts *configOptions) error {
	storeData, err := os.ReadFile(opts.storePath)
	if err != nil {
		return fmt.Errorf("failed to read store json file: %w", err)
	}

	provider, err := providers.NewJSONProviderFromJSON(string(storeData))
	if err != nil {
		return fmt.Errorf("failed to parse store json file: %w", err)
	}

	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config json file: %w", err)
	}

	serverCfg, err := configpkg.NewServerConfigFromJSON(string(configData), provider)
	if err != nil {
		return fmt.Errorf("failed to parse config json file: %w", err)
	}
	if err := serverCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate server config: %w", err)
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

	fmt.Println(clientCfg.ToURL(false))
	return nil
}
