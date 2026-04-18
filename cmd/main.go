package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	_ "github.com/theairblow/turnable/pkg/common"
)

// main runs the specified command
func main() {
	root := &cobra.Command{
		Use:           "turnable",
		Short:         "VPN core for stealthy tunneling through TURN or via SFU",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newServerCommand())
	root.AddCommand(newClientCommand())
	root.AddCommand(newKeygenCommand())
	root.AddCommand(newConfigCommand())

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
