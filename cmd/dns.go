package main

import (
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
)

// newCacheDNSCommand creates the cache DNS cobra command
func newCacheDNSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache-dns",
		Short: "Warms up the DNS cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cacheDNSMain()
		},
	}

	return cmd
}

// cacheDNSMain runs the cache DNS command
func cacheDNSMain() error {
	err := common.ResolveAll()

	if err != nil {
		slog.Info("successfully warmed up the DNS cache")
	}

	return err
}
