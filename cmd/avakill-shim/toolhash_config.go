package main

// ToolHashConfig controls tool definition hashing and rug-pull detection.
type ToolHashConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Action         string `yaml:"action"`            // "log", "warn", "block"
	ManifestDir    string `yaml:"manifest_dir"`
	PinOnFirstSeen bool   `yaml:"pin_on_first_seen"`
}
