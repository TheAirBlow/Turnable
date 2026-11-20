package version

import (
	"runtime/debug"
	"strings"
)

// Version is the Turnable version value set at build time
var Version string

const modulePath = "github.com/theairblow/turnable"

// String returns the injected version, else the module version or VCS revision from build info
func String() string {
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	// imported as a library: the version the main module requires
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		return dep.Version
	}

	if info.Main.Path == modulePath && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && setting.Value != "" {
			if len(setting.Value) > 8 {
				return setting.Value[:8]
			}
			return setting.Value
		}
	}

	return "dev"
}
