package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/service"
)

// serviceServerOptions holds CLI flags for the service server subcommand
type serviceServerOptions struct {
	configPath string
	verbose    bool
}

// newServiceCommand creates the service cobra command
func newServiceCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "service",
		Short: "Service mode server and client",
	}

	root.AddCommand(newServiceServerCommand())
	root.AddCommand(newServiceClientCommand())
	return root
}

// newServiceServerCommand creates the generate config cobra command
func newServiceServerCommand() *cobra.Command {
	opts := &serviceServerOptions{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Starts the service server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return serviceServerMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "service.json", "service config JSON file path")
	return cmd
}

// newServiceClientCommand creates the generate config cobra command
func newServiceClientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cli",
		Short: "Starts the service REPL client",
		RunE: func(cmd *cobra.Command, args []string) error {
			return serviceClientMain()
		},
	}

	return cmd
}

// serviceServerMain runs the config command
func serviceServerMain(opts *serviceServerOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	config.Options.Interactive = false

	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read cfg json file: %w", err)
	}

	cfg, err := config.NewServiceConfigFromJSON(string(configData))
	if err != nil {
		return fmt.Errorf("failed to parse cfg json file: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate service cfg: %w", err)
	}

	slog.Info("starting service server")
	server, err := service.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("invalid service cfg: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start service server: %w", err)
	}

	slog.Info("service server started")

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

	slog.Info("stopping service server")
	if err := server.Stop(); err != nil {
		return fmt.Errorf("failed to stop service server: %w", err)
	}

	return nil
}

// serviceClientMain runs the config command
func serviceClientMain() error {
	return errors.New("not implemented")
}
