package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine"
	"github.com/theairblow/turnable/pkg/engine/tunnels"
)

type clientOptions struct {
	connectionURL string
	listenAddr    string
	verbose       bool
}

func newClientCommand() *cobra.Command {
	opts := &clientOptions{}

	cmd := &cobra.Command{
		Use:   "client <connection-url>",
		Short: "Run in client mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("expected exactly one positional argument: <connection-url>")
			}
			opts.connectionURL = args[0]
			return clientMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.listenAddr, "listen", "l", "127.0.0.1:0", "local TCP/UDP listen address (ip:port)")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "enable verbose debug logging")

	return cmd
}

func clientMain(opts *clientOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	cfg, err := config.NewClientConfigFromURL(opts.connectionURL)
	if err != nil {
		return common.WrapError("failed to parse connection URL", err)
	}
	if err := cfg.Validate(); err != nil {
		return common.WrapError("failed to validate connection URL", err)
	}

	tunnelHandler := &tunnels.SocketHandler{LocalAddr: opts.listenAddr}

	client := engine.NewVPNClient(*cfg)
	if err := client.Start(tunnelHandler); err != nil {
		return common.WrapError("failed to start vpn client", err)
	}

	slog.Info("client started", "socket", cfg.Socket, "connection_type", cfg.Type, "listen", opts.listenAddr)

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
	if err := client.Stop(); err != nil {
		return common.WrapError("failed to stop vpn client", err)
	}
	return nil
}
