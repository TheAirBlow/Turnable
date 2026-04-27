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
		return fmt.Errorf("failed to read cfg json file: %w", err)
	}

	cfg, err := config.NewServerConfigFromJSON(string(configData))
	if err != nil {
		return fmt.Errorf("failed to parse cfg json file: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate server cfg: %w", err)
	}

	slog.Info("starting turnable server")
	server := engine.NewTurnableServer(*cfg)
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start VPN server: %w", err)
	}

	slog.Info("turnable server started")

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

	slog.Info("stopping turnable server")
	if err := server.Stop(); err != nil {
		return fmt.Errorf("failed to stop VPN server: %w", err)
	}

	return nil
}
