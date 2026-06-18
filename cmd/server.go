package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine"
)

// serverOptions holds CLI flags for the server subcommand
type serverOptions struct {
	configPath string
	verbose    bool
}

// newServerCommand creates the server cobra command
func newServerCommand() *cobra.Command {
	opts := &serverOptions{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run in server mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			return serverMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "config.json", "server config JSON file path")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "V", false, "enable verbose debug logging")
	return cmd
}

// serverMain runs the server command
func serverMain(opts *serverOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	config.Options.Interactive = false

	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config json file: %w", err)
	}

	serversConfig, err := config.ParseServersConfig(configData)
	if err != nil {
		return fmt.Errorf("failed to parse config json file: %w", err)
	}

	slog.Info("starting turnable servers")

	var servers []*engine.TurnableServer

	for serverKey := range serversConfig.Servers {
		serverConfig, err := serversConfig.GetServerConfig(serverKey)
		if err != nil {
			return fmt.Errorf("failed to get config for server %q: %w", serverKey, err)
		}

		innerCfg := serverConfig.GetInner().(config.ServerConfig)
		providerConfig, err := serversConfig.GetProvider(innerCfg.Provider)
		if err != nil {
			return fmt.Errorf("failed to get provider for server %q: %w", serverKey, err)
		}

		providerData := serversConfig.Providers[innerCfg.Provider]
		if err := providerConfig.Update(providerData); err != nil {
			return fmt.Errorf("failed to update provider for server %q: %w", serverKey, err)
		}

		server := engine.NewTurnableServer(serverConfig, providerConfig)
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start server %q: %w", serverKey, err)
		}

		servers = append(servers, server)
		slog.Info("started server instance", "server", serverKey)
	}

	slog.Info("all turnable servers started")

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	<-sigCh
	slog.Warn("CTRL+C received, stopping gracefully...")
	go func() {
		<-sigCh
		slog.Error("CTRL+C received, forcibly exiting...")
		os.Exit(130)
	}()

	slog.Info("stopping turnable servers")
	for _, server := range servers {
		if err := server.Stop(); err != nil {
			slog.Error("failed to stop server", "error", err)
		}
	}

	return nil
}
