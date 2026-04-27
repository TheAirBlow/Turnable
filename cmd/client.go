package main

import (
	"context"
	"errors"
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

// clientOptions holds CLI flags for the client subcommand
type clientOptions struct {
	configPath    string
	configURL     string
	listenAddr    string
	noInteractive bool
	verbose       bool
}

// newClientCommand creates the Client cobra command
func newClientCommand() *cobra.Command {
	opts := &clientOptions{}

	cmd := &cobra.Command{
		Use:   "client [config-url]",
		Short: "Run in client mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.configURL = args[0]
			}

			return clientMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.listenAddr, "listen", "l", "127.0.0.1:0", "local TCP/UDP listen listenAddr (ip:port)")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "V", false, "enable verbose debug logging")
	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "config.json", "client config JSON file path")
	cmd.Flags().BoolVarP(&opts.noInteractive, "no-interactive", "i", false, "disable interactive mode")

	return cmd
}

// serverMain runs the client command
func clientMain(opts *clientOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	config.Options.Interactive = !opts.noInteractive

	var cfg *config.ClientConfig
	if !common.IsNullOrWhiteSpace(opts.configURL) {
		var err error
		cfg, err = config.NewClientConfigFromURL(opts.configURL)
		if err != nil {
			return fmt.Errorf("failed to parse config URL: %w", err)
		}
	} else if !common.IsNullOrWhiteSpace(opts.configPath) {
		configData, err := os.ReadFile(opts.configPath)
		if err != nil {
			return fmt.Errorf("failed to read config json file: %w", err)
		}

		cfg, err = config.NewClientConfigFromJSON(string(configData))
		if err != nil {
			return err
		}
	} else {
		return errors.New("either config-url or config path is required")
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate connection URL: %w", err)
	}

	slog.Info("starting turnable client", "connection_type", cfg.Type)
	client := engine.NewTurnableClient(*cfg)
	if err := client.Start(opts.listenAddr); err != nil {
		return fmt.Errorf("failed to start vpn client: %w", err)
	}

	slog.Info("turnable client started", "socket", cfg.Socket, "connection_type", cfg.Type, "listen", opts.listenAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		<-sigCh
		slog.Warn("shutdown signal received, stopping gracefully; press Ctrl+C again to force exit")
		cancel()

		<-sigCh
		slog.Error("second shutdown signal received, forcing immediate exit")
		os.Exit(130)
	}()

	<-ctx.Done()

	slog.Info("stopping turnable client")
	if err := client.Stop(); err != nil {
		return fmt.Errorf("failed to stop vpn client: %w", err)
	}

	return nil
}
