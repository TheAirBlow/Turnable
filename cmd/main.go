package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	_ "github.com/theairblow/turnable/pkg/common"
)

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "turnable",
		Short:         "MAX/VK TURN VPN",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newServerCommand())
	rootCmd.AddCommand(newClientCommand())
	rootCmd.AddCommand(newKeygenCommand())
	rootCmd.AddCommand(newConfigCommand())

	return rootCmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
