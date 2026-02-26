package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyConfig mirrors the top-level YAML policy structure.
type PolicyConfig struct {
	Version       string          `yaml:"version"`
	DefaultAction string          `yaml:"default_action"`
	Policies      []PolicyRule    `yaml:"policies"`
	ToolHash      *ToolHashConfig `yaml:"tool_hash,omitempty"`
}

// PolicyRule mirrors a single rule inside the policies list.
type PolicyRule struct {
	Name       string          `yaml:"name"`
	Tools      []string        `yaml:"tools"`
	Action     string          `yaml:"action"`
	Message    string          `yaml:"message,omitempty"`
	Conditions *RuleConditions `yaml:"conditions,omitempty"`
	RateLimit  *RateLimit      `yaml:"rate_limit,omitempty"`
}

// RuleConditions holds optional matching conditions for a rule.
type RuleConditions struct {
	ArgsMatch        map[string][]string `yaml:"args_match,omitempty"`
	ArgsNotMatch     map[string][]string `yaml:"args_not_match,omitempty"`
	ShellSafe        bool                `yaml:"shell_safe,omitempty"`
	CommandAllowlist []string            `yaml:"command_allowlist,omitempty"`
	PathMatch        []string            `yaml:"path_match,omitempty"`
	PathNotMatch     []string            `yaml:"path_not_match,omitempty"`
}

// RateLimit configures a sliding-window rate limit for a rule.
type RateLimit struct {
	MaxCalls int    `yaml:"max_calls"`
	Window   string `yaml:"window"`
}

// loadPolicyFile reads and unmarshals a YAML policy file.
func loadPolicyFile(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateConfig checks a parsed PolicyConfig for correctness.
func validateConfig(cfg *PolicyConfig) error {
	// Normalize version: YAML may parse unquoted 1.0 as "1" (float → int)
	switch cfg.Version {
	case "1", "1.0":
		cfg.Version = "1.0"
	case "":
		return fmt.Errorf("policy version is required")
	default:
		return fmt.Errorf("unsupported policy version %q (expected \"1.0\")", cfg.Version)
	}

	switch cfg.DefaultAction {
	case "allow", "deny":
		// ok
	case "":
		return fmt.Errorf("default_action is required")
	default:
		return fmt.Errorf("invalid default_action %q (expected \"allow\" or \"deny\")", cfg.DefaultAction)
	}

	// Validate tool_hash config
	if cfg.ToolHash != nil && cfg.ToolHash.Enabled {
		switch cfg.ToolHash.Action {
		case "log", "warn", "block":
			// ok
		case "":
			cfg.ToolHash.Action = "warn"
		default:
			return fmt.Errorf("tool_hash: invalid action %q (expected \"log\", \"warn\", or \"block\")", cfg.ToolHash.Action)
		}
		if cfg.ToolHash.ManifestDir == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				cfg.ToolHash.ManifestDir = filepath.Join(home, ".avakill", "tool-manifests")
			}
		}
	}

	for i, rule := range cfg.Policies {
		if rule.Name == "" {
			return fmt.Errorf("policy[%d]: name is required", i)
		}
		if len(rule.Tools) == 0 {
			return fmt.Errorf("policy %q: tools list is required", rule.Name)
		}
		switch rule.Action {
		case "allow", "deny", "require_approval":
			// ok
		default:
			return fmt.Errorf("policy %q: invalid action %q", rule.Name, rule.Action)
		}
	}

	return nil
}

// matchTool checks if a tool name matches any of the given patterns.
// Supports exact match, filepath.Match glob patterns, and the
// special values "all" and "*" which match everything.
func matchTool(toolName string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == "all" {
			return true
		}
		matched, err := filepath.Match(pattern, toolName)
		if err != nil {
			// Malformed pattern (e.g. unclosed bracket) — treat as non-match
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// checkConditions evaluates rule conditions against tool call arguments.
//
// args_match: ALL keys must match (AND across keys). For each key, the
// argument value (as a string, case-insensitive) must contain at least
// one of the specified substrings (OR within each key).
//
// args_not_match: if ANY key's argument value contains any of the
// specified substrings, the condition fails (returns false).
func checkConditions(args map[string]interface{}, conds *RuleConditions) bool {
	if conds == nil {
		return true
	}

	// args_match: AND across keys, OR within each key's substrings
	for key, substrings := range conds.ArgsMatch {
		value := strings.ToLower(stringifyArg(args[key]))
		matched := false
		for _, s := range substrings {
			if strings.Contains(value, strings.ToLower(s)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// args_not_match: if any substring matches, condition fails
	for key, substrings := range conds.ArgsNotMatch {
		value := strings.ToLower(stringifyArg(args[key]))
		for _, s := range substrings {
			if strings.Contains(value, strings.ToLower(s)) {
				return false
			}
		}
	}

	// path_match: extract paths from args, normalize, check if ANY matches ANY pattern
	if len(conds.PathMatch) > 0 {
		workspace := cachedWorkspaceRoot()
		rawPaths := extractPaths(args)
		matched := false
		for _, raw := range rawPaths {
			normalized := normalizePath(raw, workspace)
			if matchPath(normalized, conds.PathMatch, workspace) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// path_not_match: forbidden path patterns. The rule fires when ANY extracted
	// path matches ANY pattern (i.e., a blacklist). If no path matches, the
	// condition fails and the rule is skipped.
	if len(conds.PathNotMatch) > 0 {
		workspace := cachedWorkspaceRoot()
		rawPaths := extractPaths(args)
		matched := false
		for _, raw := range rawPaths {
			normalized := normalizePath(raw, workspace)
			if matchPath(normalized, conds.PathNotMatch, workspace) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// shell_safe: check command via AST analysis (AND with other conditions)
	if conds.ShellSafe {
		cmd := extractCommand(args)
		if cmd != "" {
			safe, _ := isShellSafe(cmd, conds.CommandAllowlist)
			if !safe {
				return false
			}
		}
	}

	return true
}

// extractCommand extracts the shell command string from tool call arguments.
// Tries "command" key first, then "cmd" as fallback.
func extractCommand(args map[string]interface{}) string {
	if v, ok := args["command"]; ok {
		return stringifyArg(v)
	}
	if v, ok := args["cmd"]; ok {
		return stringifyArg(v)
	}
	return ""
}

// stringifyArg converts any argument value to a string, matching
// Python's str() behavior for common JSON types.
func stringifyArg(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers unmarshal as float64
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// parseWindow converts a duration string like "60s", "5m", or "1h"
// to seconds. Returns 0 on invalid input.
func parseWindow(window string) int {
	if window == "" {
		return 0
	}

	// Try bare integer (seconds)
	if secs, err := strconv.Atoi(window); err == nil {
		return secs
	}

	suffix := window[len(window)-1]
	numStr := window[:len(window)-1]
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0
	}

	switch suffix {
	case 's':
		return num
	case 'm':
		return num * 60
	case 'h':
		return num * 3600
	default:
		return 0
	}
}

// rateLimitState tracks per-tool call timestamps for sliding-window rate limiting.
type rateLimitState struct {
	mu      sync.Mutex
	windows map[string][]time.Time // tool name → sorted timestamps
}

func newRateLimitState() *rateLimitState {
	return &rateLimitState{
		windows: make(map[string][]time.Time),
	}
}

// check returns true if the tool call is within the rate limit.
func (r *rateLimitState) check(toolName string, rl *RateLimit) bool {
	if rl == nil {
		return true
	}

	windowSecs := parseWindow(rl.Window)
	if windowSecs <= 0 {
		return true
	}

	now := time.Now()
	cutoff := now.Add(-time.Duration(windowSecs) * time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()

	timestamps := r.windows[toolName]

	// Purge expired entries
	valid := 0
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			timestamps[valid] = ts
			valid++
		}
	}
	timestamps = timestamps[:valid]

	if len(timestamps) >= rl.MaxCalls {
		r.windows[toolName] = timestamps
		return false
	}

	r.windows[toolName] = append(timestamps, now)
	return true
}

// PolicyCache provides mtime-based hot-reloading of a YAML policy file.
type PolicyCache struct {
	path      string
	mu        sync.RWMutex
	config    *PolicyConfig
	modTime   time.Time
	rateState *rateLimitState
	verbose   bool
}

// NewPolicyCache creates a new PolicyCache for the given file path.
func NewPolicyCache(path string, verbose bool) *PolicyCache {
	return &PolicyCache{
		path:      path,
		rateState: newRateLimitState(),
		verbose:   verbose,
	}
}

// getConfig returns the current PolicyConfig, reloading from disk if the
// file's mtime has changed. Thread-safe via RWMutex.
func (pc *PolicyCache) getConfig() (*PolicyConfig, error) {
	info, err := os.Stat(pc.path)
	if err != nil {
		return nil, fmt.Errorf("stat policy file: %w", err)
	}

	mtime := info.ModTime()

	// Fast path: cached config is fresh
	pc.mu.RLock()
	if pc.config != nil && mtime.Equal(pc.modTime) {
		cfg := pc.config
		pc.mu.RUnlock()
		return cfg, nil
	}
	pc.mu.RUnlock()

	// Slow path: reload
	cfg, err := loadPolicyFile(pc.path)
	if err != nil {
		return nil, err
	}

	pc.mu.Lock()
	pc.config = cfg
	pc.modTime = mtime
	pc.mu.Unlock()

	if pc.verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: loaded policy %s (%d rules, default=%s)\n",
			pc.path, len(cfg.Policies), cfg.DefaultAction)
	}

	return cfg, nil
}

// Evaluate runs first-match-wins evaluation against the cached policy.
func (pc *PolicyCache) Evaluate(tool string, args map[string]interface{}) (EvaluateResponse, error) {
	start := time.Now()

	cfg, err := pc.getConfig()
	if err != nil {
		return EvaluateResponse{}, err
	}

	for _, rule := range cfg.Policies {
		if !matchTool(tool, rule.Tools) {
			continue
		}

		if rule.Conditions != nil && !checkConditions(args, rule.Conditions) {
			continue
		}

		// Rule matches — check rate limit
		if rule.RateLimit != nil {
			if !pc.rateState.check(tool, rule.RateLimit) {
				elapsed := float64(time.Since(start).Microseconds()) / 1000.0
				return EvaluateResponse{
					Decision:  "deny",
					Reason:    fmt.Sprintf("Rate limit exceeded: %d calls per %s", rule.RateLimit.MaxCalls, rule.RateLimit.Window),
					Policy:    rule.Name,
					LatencyMs: elapsed,
				}, nil
			}
		}

		elapsed := float64(time.Since(start).Microseconds()) / 1000.0

		action := rule.Action
		reason := rule.Message
		if reason == "" {
			reason = fmt.Sprintf("Matched rule '%s'", rule.Name)
		}

		// require_approval → deny in MCP context (no interactive approval)
		if action == "require_approval" {
			action = "deny"
			if rule.Message == "" {
				reason = fmt.Sprintf("Matched rule '%s' (require_approval treated as deny)", rule.Name)
			}
		}

		decision := "allow"
		if action == "deny" {
			decision = "deny"
		}

		return EvaluateResponse{
			Decision:  decision,
			Reason:    reason,
			Policy:    rule.Name,
			LatencyMs: elapsed,
		}, nil
	}

	// No rule matched — use default action
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	decision := cfg.DefaultAction
	return EvaluateResponse{
		Decision:  decision,
		Reason:    fmt.Sprintf("No matching rule; default action is '%s'", cfg.DefaultAction),
		LatencyMs: elapsed,
	}, nil
}
