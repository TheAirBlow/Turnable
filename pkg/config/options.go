package config

// GlobalOptions represents global options
type GlobalOptions struct {
	Interactive bool // Allow interactive operations
}

// Options holds the process-wide options
var Options GlobalOptions
