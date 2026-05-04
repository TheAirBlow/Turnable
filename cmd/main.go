package main

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	_ "github.com/theairblow/turnable/pkg/common"
)

var buildVersion string

// main runs the specified command
func main() {
	root := &cobra.Command{
		Use:           "turnable",
		Short:         "VPN core for stealthy tunneling through TURN or via SFU",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = versionString()
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(newServerCommand())
	root.AddCommand(newClientCommand())
	root.AddCommand(newConfigCommand())
	root.AddCommand(newServiceCommand())
	root.AddCommand(newCacheDNSCommand())

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// versionString constructs the version string for this build
func versionString() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				if len(setting.Value) > 8 {
					return setting.Value[:8]
				}
				return setting.Value
			}
		}
	}

	return "dev"
}
