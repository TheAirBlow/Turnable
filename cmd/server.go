package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	config2 "github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/engine"
)

type serverOptions struct {
	configPath string
	storePath  string
	verbose    bool
}

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
	cmd.Flags().StringVarP(&opts.storePath, "store", "s", "store.json", "server user/route store JSON file path")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "enable verbose debug logging")
	return cmd
}

func serverMain(opts *serverOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	storeData, err := os.ReadFile(opts.storePath)
	if err != nil {
		return common.WrapError("failed to read store json file", err)
	}

	provider, err := providers.NewJSONProviderFromJSON(string(storeData))
	if err != nil {
		return common.WrapError("failed to parse store json file", err)
	}

	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return common.WrapError("failed to read config json file", err)
	}

	config, err := config2.NewServerConfigFromJSON(string(configData), provider)
	if err != nil {
		return common.WrapError("failed to parse config json file", err)
	}

	err = config.Validate()
	if err != nil {
		return common.WrapError("failed to validate server config", err)
	}

	server := engine.NewVPNServer(*config)
	if err := server.Start(); err != nil {
		return common.WrapError("failed to start VPN server", err)
	}

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

	if err := server.Stop(); err != nil {
		return common.WrapError("failed to stop VPN server", err)
	}

	return nil
}
