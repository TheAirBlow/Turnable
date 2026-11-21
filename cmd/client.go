package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine"
)

// clientOptions holds CLI flags for the client subcommand
type clientOptions struct {
	config        string   // config URL, JSON file or file with a config URL
	listenAddrs   []string // local listen addresses, one per route
	noInteractive bool     // disable interactive prompts
	verbose       bool     // enable debug logging
}

// newClientCommand creates the Client cobra command
func newClientCommand() *cobra.Command {
	opts := &clientOptions{}

	cmd := &cobra.Command{
		Use:   "client [config]",
		Short: "Run in client mode",
		Long:  "Run in client mode. The config is a turnable:// URL, an http(s):// subscription URL (interactive mode only), a path to a .json file, or a path to a file holding a single-line URL. Defaults to config.json.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.config = args[0]
			}

			return clientMain(opts)
		},
	}

	cmd.Flags().StringArrayVarP(&opts.listenAddrs, "listen", "l", []string{"127.0.0.1:0"}, "local listen addresses, one per route")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "V", false, "enable verbose debug logging")
	cmd.Flags().BoolVarP(&opts.noInteractive, "no-interactive", "i", false, "disable interactive mode")

	return cmd
}

// readClientConfig loads config content from a URL, a JSON file or a file with a single-line URL
func readClientConfig(arg string) ([]byte, error) {
	if common.IsNullOrWhiteSpace(arg) {
		arg = "config.json"
	}

	if strings.Contains(arg, "://") {
		return []byte(arg), nil
	}

	data, err := os.ReadFile(arg)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if !strings.EqualFold(filepath.Ext(arg), ".json") && bytes.ContainsRune(bytes.TrimSpace(data), '\n') {
		return nil, fmt.Errorf("%s is not a .json file and does not contain a single-line config URL", arg)
	}

	return data, nil
}

// clientMain runs the client command
func clientMain(opts *clientOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	config.Options.Interactive = !opts.noInteractive

	raw, err := readClientConfig(opts.config)
	if err != nil {
		return err
	}

	if isSubscriptionURL(raw) {
		if raw, err = resolveSubscription(string(raw)); err != nil {
			return err
		}
	}

	cfg, err := config.ParseClientConfig(raw)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate connection URL: %w", err)
	}

	innerCfg := cfg.GetInner().(config.ClientConfig)

	client := engine.NewTurnableClient(cfg)
	if err := client.Start(opts.listenAddrs); err != nil {
		return fmt.Errorf("failed to start vpn client: %w", err)
	}

	slog.Info("turnable client started", "routes", len(innerCfg.Routes), "connection_type", innerCfg.Type, "listen", opts.listenAddrs)

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
