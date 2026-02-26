package main

// ScanConfig configures response scanning behavior.
type ScanConfig struct {
	Enabled        bool            `yaml:"enabled"`
	Action         string          `yaml:"action"`          // "log", "redact", "block"
	ScanSecrets    bool            `yaml:"scan_secrets"`
	ScanPII        bool            `yaml:"scan_pii"`
	ScanInjection  bool            `yaml:"scan_injection"`
	SafeDomains    []string        `yaml:"safe_domains,omitempty"`
	CustomPatterns []CustomPattern `yaml:"custom_patterns,omitempty"`
}

// CustomPattern defines a user-provided regex pattern for scanning.
type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"` // overrides ScanConfig.Action
}
