package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	_ "github.com/theairblow/turnable/pkg/common"
	_ "github.com/theairblow/turnable/pkg/init"
	"github.com/theairblow/turnable/pkg/version"
)

// main runs the specified command
func main() {
	root := &cobra.Command{
		Use:           "turnable",
		Short:         "VPN core for stealthy tunneling through TURN or via SFU",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = version.String()
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(newServerCommand())
	root.AddCommand(newClientCommand())
	root.AddCommand(newConfigCommand())
	root.AddCommand(newServiceCommand())
	root.AddCommand(newCacheDNSCommand())
	root.AddCommand(newUpdateCommand())

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
