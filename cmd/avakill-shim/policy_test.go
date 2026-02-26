package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- YAML parsing tests ---

func TestLoadPolicyFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1.0"
default_action: allow
policies:
  - name: block-writes
    tools: ["write_file"]
    action: deny
    message: "writes blocked"
`), 0644)

	cfg, err := loadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", cfg.Version)
	}
	if cfg.DefaultAction != "allow" {
		t.Errorf("expected default_action allow, got %q", cfg.DefaultAction)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cfg.Policies))
	}
	if cfg.Policies[0].Name != "block-writes" {
		t.Errorf("expected policy name 'block-writes', got %q", cfg.Policies[0].Name)
	}
}

func TestLoadPolicyFile_MissingFile(t *testing.T) {
	_, err := loadPolicyFile("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPolicyFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(`{not valid yaml: [`), 0644)

	_, err := loadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadPolicyFile_BadVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "2.0"
default_action: allow
policies: []
`), 0644)

	_, err := loadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestLoadPolicyFile_VersionNormalization(t *testing.T) {
	// YAML parses unquoted `version: 1.0` as float → string "1"
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: 1
default_action: allow
policies: []
`), 0644)

	cfg, err := loadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != "1.0" {
		t.Errorf("expected version '1.0' after normalization, got %q", cfg.Version)
	}
}

func TestLoadPolicyFile_BadDefaultAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1.0"
default_action: maybe
policies: []
`), 0644)

	_, err := loadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for bad default_action")
	}
}

func TestLoadPolicyFile_EmptyTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1.0"
default_action: allow
policies:
  - name: no-tools
    tools: []
    action: deny
`), 0644)

	_, err := loadPolicyFile(path)
	if err == nil {
		t.Fatal("expected error for empty tools list")
	}
}

// --- Tool matching tests ---

func TestMatchTool_Exact(t *testing.T) {
	if !matchTool("read_file", []string{"read_file"}) {
		t.Error("expected exact match")
	}
}

func TestMatchTool_GlobPrefix(t *testing.T) {
	if !matchTool("shell_execute", []string{"shell_*"}) {
		t.Error("expected glob prefix match")
	}
}

func TestMatchTool_GlobSuffix(t *testing.T) {
	if !matchTool("run_command", []string{"*_command"}) {
		t.Error("expected glob suffix match")
	}
}

func TestMatchTool_Star(t *testing.T) {
	if !matchTool("anything", []string{"*"}) {
		t.Error("expected '*' to match everything")
	}
}

func TestMatchTool_All(t *testing.T) {
	if !matchTool("anything", []string{"all"}) {
		t.Error("expected 'all' to match everything")
	}
}

func TestMatchTool_NoMatch(t *testing.T) {
	if matchTool("read_file", []string{"write_file", "delete_file"}) {
		t.Error("expected no match")
	}
}

func TestMatchTool_BadPattern(t *testing.T) {
	// Malformed glob pattern with unclosed bracket
	if matchTool("test", []string{"[unclosed"}) {
		t.Error("expected malformed pattern to not match")
	}
}

func TestMatchTool_MultiplePatterns(t *testing.T) {
	if !matchTool("write_file", []string{"read_file", "write_*"}) {
		t.Error("expected match on second pattern")
	}
}

// --- Condition checking tests ---

func TestCheckConditions_ArgsMatch_Pass(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"rm -rf /"},
		},
	}
	args := map[string]interface{}{
		"command": "sudo rm -rf / --no-preserve-root",
	}
	if !checkConditions(args, conds) {
		t.Error("expected args_match to pass (substring match)")
	}
}

func TestCheckConditions_ArgsMatch_Fail(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"rm -rf /"},
		},
	}
	args := map[string]interface{}{
		"command": "ls -la",
	}
	if checkConditions(args, conds) {
		t.Error("expected args_match to fail")
	}
}

func TestCheckConditions_ArgsMatch_CaseInsensitive(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"DROP DATABASE"},
		},
	}
	args := map[string]interface{}{
		"command": "drop database production",
	}
	if !checkConditions(args, conds) {
		t.Error("expected case-insensitive match")
	}
}

func TestCheckConditions_ArgsMatch_MissingKey(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"rm"},
		},
	}
	args := map[string]interface{}{
		"path": "/tmp",
	}
	// Missing key → empty string → no substring match → fails
	if checkConditions(args, conds) {
		t.Error("expected args_match to fail when key is missing")
	}
}

func TestCheckConditions_ArgsNotMatch_Pass(t *testing.T) {
	conds := &RuleConditions{
		ArgsNotMatch: map[string][]string{
			"path": {"/etc", "/root"},
		},
	}
	args := map[string]interface{}{
		"path": "/tmp/test.txt",
	}
	if !checkConditions(args, conds) {
		t.Error("expected args_not_match to pass (no banned substring)")
	}
}

func TestCheckConditions_ArgsNotMatch_Fail(t *testing.T) {
	conds := &RuleConditions{
		ArgsNotMatch: map[string][]string{
			"path": {"/etc", "/root"},
		},
	}
	args := map[string]interface{}{
		"path": "/etc/passwd",
	}
	if checkConditions(args, conds) {
		t.Error("expected args_not_match to fail (banned substring found)")
	}
}

func TestCheckConditions_MultiKey_AND(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"install"},
			"mode":    {"global"},
		},
	}
	args := map[string]interface{}{
		"command": "pip install requests",
		"mode":    "global",
	}
	if !checkConditions(args, conds) {
		t.Error("expected multi-key AND to pass")
	}

	// Fail: only one key matches
	args2 := map[string]interface{}{
		"command": "pip install requests",
		"mode":    "local",
	}
	if checkConditions(args2, conds) {
		t.Error("expected multi-key AND to fail when one key doesn't match")
	}
}

func TestCheckConditions_NonStringValues(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"count": {"42"},
		},
	}
	args := map[string]interface{}{
		"count": float64(42), // JSON numbers are float64
	}
	if !checkConditions(args, conds) {
		t.Error("expected numeric arg to match after stringification")
	}
}

func TestCheckConditions_BoolValues(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"force": {"true"},
		},
	}
	args := map[string]interface{}{
		"force": true,
	}
	if !checkConditions(args, conds) {
		t.Error("expected bool arg to match after stringification")
	}
}

func TestCheckConditions_NilConditions(t *testing.T) {
	args := map[string]interface{}{"foo": "bar"}
	if !checkConditions(args, nil) {
		t.Error("nil conditions should always pass")
	}
}

func TestCheckConditions_NilArgs(t *testing.T) {
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"rm"},
		},
	}
	if checkConditions(nil, conds) {
		t.Error("nil args with args_match should fail")
	}
}

// --- Rate limiting tests ---

func TestRateLimit_WithinLimit(t *testing.T) {
	state := newRateLimitState()
	rl := &RateLimit{MaxCalls: 3, Window: "60s"}

	for i := 0; i < 3; i++ {
		if !state.check("test_tool", rl) {
			t.Errorf("call %d should be within limit", i+1)
		}
	}
}

func TestRateLimit_Exceeded(t *testing.T) {
	state := newRateLimitState()
	rl := &RateLimit{MaxCalls: 2, Window: "60s"}

	state.check("test_tool", rl) // 1
	state.check("test_tool", rl) // 2

	if state.check("test_tool", rl) {
		t.Error("3rd call should exceed limit of 2")
	}
}

func TestRateLimit_WindowExpiry(t *testing.T) {
	state := newRateLimitState()
	rl := &RateLimit{MaxCalls: 1, Window: "1s"}

	state.check("test_tool", rl)

	// Manually backdate the timestamp
	state.mu.Lock()
	state.windows["test_tool"][0] = time.Now().Add(-2 * time.Second)
	state.mu.Unlock()

	if !state.check("test_tool", rl) {
		t.Error("call should succeed after window expiry")
	}
}

func TestRateLimit_PerToolIsolation(t *testing.T) {
	state := newRateLimitState()
	rl := &RateLimit{MaxCalls: 1, Window: "60s"}

	state.check("tool_a", rl)

	// tool_b should have its own counter
	if !state.check("tool_b", rl) {
		t.Error("tool_b should have independent counter")
	}
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"60s", 60},
		{"5m", 300},
		{"1h", 3600},
		{"30", 30},
		{"1m", 60},
		{"", 0},
		{"bad", 0},
	}

	for _, tc := range tests {
		got := parseWindow(tc.input)
		if got != tc.expected {
			t.Errorf("parseWindow(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

// --- Full evaluation tests ---

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: block-writes
    tools: ["write_file"]
    action: deny
    message: "writes blocked"
  - name: allow-all
    tools: ["all"]
    action: allow
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny (first match), got %q", resp.Decision)
	}
	if resp.Policy != "block-writes" {
		t.Errorf("expected policy 'block-writes', got %q", resp.Policy)
	}
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: deny
policies:
  - name: allow-reads
    tools: ["read_file"]
    action: allow
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("write_file", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected default deny, got %q", resp.Decision)
	}
}

func TestEvaluate_DefaultAllow(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: block-writes
    tools: ["write_file"]
    action: deny
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("read_file", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected default allow, got %q", resp.Decision)
	}
}

func TestEvaluate_RequireApprovalTreatedAsDeny(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: approve-installs
    tools: ["shell_execute"]
    action: require_approval
    conditions:
      args_match:
        command: ["pip install"]
    message: "Package install requires approval."
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("shell_execute", map[string]interface{}{"command": "pip install requests"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected require_approval to be treated as deny, got %q", resp.Decision)
	}
	if resp.Reason != "Package install requires approval." {
		t.Errorf("expected custom message, got %q", resp.Reason)
	}
}

func TestEvaluate_CustomMessage(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: block-rm
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf /"]
    message: "Catastrophic command blocked."
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("shell_execute", map[string]interface{}{"command": "rm -rf /"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Reason != "Catastrophic command blocked." {
		t.Errorf("expected custom message, got %q", resp.Reason)
	}
}

func TestEvaluate_LatencyPopulated(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies: []
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("any_tool", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.LatencyMs < 0 {
		t.Errorf("latency should be non-negative, got %f", resp.LatencyMs)
	}
}

func TestEvaluate_RateLimitDeny(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: rate-test
    tools: ["spawn_agent"]
    action: allow
    rate_limit:
      max_calls: 2
      window: "60s"
`)

	cache := NewPolicyCache(path, false)
	cache.Evaluate("spawn_agent", nil) // 1
	cache.Evaluate("spawn_agent", nil) // 2

	resp, err := cache.Evaluate("spawn_agent", nil) // 3 → denied
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected rate limit deny, got %q", resp.Decision)
	}
	if resp.Policy != "rate-test" {
		t.Errorf("expected policy 'rate-test', got %q", resp.Policy)
	}
}

func TestEvaluate_ConditionsSkipRule(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies:
  - name: block-dangerous
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf /"]
  - name: log-all
    tools: ["all"]
    action: allow
`)

	cache := NewPolicyCache(path, false)

	// Safe command should skip the deny rule and hit allow-all
	resp, err := cache.Evaluate("shell_execute", map[string]interface{}{"command": "ls -la"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow (conditions not met), got %q", resp.Decision)
	}
	if resp.Policy != "log-all" {
		t.Errorf("expected policy 'log-all', got %q", resp.Policy)
	}
}

// --- Cache tests ---

func TestCache_LoadsOnFirstCall(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: deny
policies: []
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny from default, got %q", resp.Decision)
	}
}

func TestCache_CachesAcrossCalls(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: allow
policies: []
`)

	cache := NewPolicyCache(path, false)

	// First call loads config
	cache.Evaluate("test", nil)

	// Get the cached config pointer
	cfg1, _ := cache.getConfig()

	// Second call should use cached config (same pointer)
	cfg2, _ := cache.getConfig()

	if cfg1 != cfg2 {
		t.Error("expected cached config to be reused (same pointer)")
	}
}

func TestCache_ReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	os.WriteFile(path, []byte(`
version: "1.0"
default_action: allow
policies: []
`), 0644)

	cache := NewPolicyCache(path, false)
	resp1, _ := cache.Evaluate("test", nil)
	if resp1.Decision != "allow" {
		t.Fatalf("expected allow, got %q", resp1.Decision)
	}

	// Modify file with different default action
	// Sleep briefly to ensure mtime changes
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(`
version: "1.0"
default_action: deny
policies: []
`), 0644)

	resp2, _ := cache.Evaluate("test", nil)
	if resp2.Decision != "deny" {
		t.Errorf("expected deny after reload, got %q", resp2.Decision)
	}
}

func TestCache_FailClosedOnBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Start with valid policy
	os.WriteFile(path, []byte(`
version: "1.0"
default_action: allow
policies: []
`), 0644)

	cache := NewPolicyCache(path, false)
	cache.Evaluate("test", nil) // loads successfully

	// Corrupt the file
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(`{broken yaml: [`), 0644)

	_, err := cache.Evaluate("test", nil)
	if err == nil {
		t.Error("expected error on bad YAML")
	}
}

func TestCache_PreservesRateStateOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	policy := `
version: "1.0"
default_action: allow
policies:
  - name: rate-test
    tools: ["spawn"]
    action: allow
    rate_limit:
      max_calls: 2
      window: "60s"
`
	os.WriteFile(path, []byte(policy), 0644)

	cache := NewPolicyCache(path, false)
	cache.Evaluate("spawn", nil) // 1
	cache.Evaluate("spawn", nil) // 2

	// Reload policy (touch file to change mtime)
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(policy), 0644)

	// Rate state should persist across reload
	resp, _ := cache.Evaluate("spawn", nil) // 3 → should still be denied
	if resp.Decision != "deny" {
		t.Errorf("expected rate limit to persist across reload, got %q", resp.Decision)
	}
}

// --- stringifyArg tests ---

func TestStringifyArg(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{"hello", "hello"},
		{nil, ""},
		{true, "true"},
		{false, "false"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{42, "42"},
	}

	for _, tc := range tests {
		got := stringifyArg(tc.input)
		if got != tc.expected {
			t.Errorf("stringifyArg(%v) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// --- shell_safe condition tests ---

func TestCheckConditions_ShellSafe_SafeCommand(t *testing.T) {
	conds := &RuleConditions{
		ShellSafe: true,
	}
	args := map[string]interface{}{
		"command": "ls -la",
	}
	if !checkConditions(args, conds) {
		t.Error("expected shell_safe to pass for safe command")
	}
}

func TestCheckConditions_ShellSafe_UnsafeCommand(t *testing.T) {
	conds := &RuleConditions{
		ShellSafe: true,
	}
	args := map[string]interface{}{
		"command": "echo $(whoami)",
	}
	if checkConditions(args, conds) {
		t.Error("expected shell_safe to fail for command substitution")
	}
}

func TestCheckConditions_ShellSafe_CmdKey(t *testing.T) {
	// Falls back to "cmd" key when "command" is absent
	conds := &RuleConditions{
		ShellSafe: true,
	}
	args := map[string]interface{}{
		"cmd": "eval malicious",
	}
	if checkConditions(args, conds) {
		t.Error("expected shell_safe to fail for eval via 'cmd' key")
	}
}

func TestCheckConditions_ShellSafe_NoCommandKey(t *testing.T) {
	// No command key at all — shell_safe is vacuously true
	conds := &RuleConditions{
		ShellSafe: true,
	}
	args := map[string]interface{}{
		"path": "/tmp",
	}
	if !checkConditions(args, conds) {
		t.Error("expected shell_safe to pass when no command key present")
	}
}

func TestCheckConditions_CommandAllowlist_Pass(t *testing.T) {
	conds := &RuleConditions{
		ShellSafe:        true,
		CommandAllowlist: []string{"ls", "git", "cat"},
	}
	args := map[string]interface{}{
		"command": "ls -la",
	}
	if !checkConditions(args, conds) {
		t.Error("expected allowlist to pass for ls")
	}
}

func TestCheckConditions_CommandAllowlist_Reject(t *testing.T) {
	conds := &RuleConditions{
		ShellSafe:        true,
		CommandAllowlist: []string{"ls", "git", "cat"},
	}
	args := map[string]interface{}{
		"command": "rm -rf /",
	}
	if checkConditions(args, conds) {
		t.Error("expected allowlist to reject rm")
	}
}

func TestCheckConditions_ShellSafe_ANDWithArgsMatch(t *testing.T) {
	conds := &RuleConditions{
		ShellSafe: true,
		ArgsMatch: map[string][]string{
			"command": {"git"},
		},
	}
	// Both conditions satisfied
	args := map[string]interface{}{
		"command": "git status",
	}
	if !checkConditions(args, conds) {
		t.Error("expected both conditions to pass")
	}

	// args_match satisfied but shell_safe fails
	args2 := map[string]interface{}{
		"command": "git $(malicious)",
	}
	if checkConditions(args2, conds) {
		t.Error("expected shell_safe to fail even when args_match passes")
	}
}

func TestCheckConditions_ShellSafe_NotSet(t *testing.T) {
	// When shell_safe is false (default), it should be a no-op
	conds := &RuleConditions{
		ArgsMatch: map[string][]string{
			"command": {"ls"},
		},
	}
	args := map[string]interface{}{
		"command": "ls $(whoami)", // would fail shell_safe, but it's not enabled
	}
	if !checkConditions(args, conds) {
		t.Error("shell_safe=false should not affect condition checking")
	}
}

// --- Full evaluation tests with shell_safe ---

func TestEvaluate_ShellSafe_AllowSafeCommand(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: deny
policies:
  - name: safe-shell
    tools: ["Bash"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: ["ls", "git", "cat"]
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("Bash", map[string]interface{}{"command": "ls -la"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow for safe command, got %q: %s", resp.Decision, resp.Reason)
	}
}

func TestEvaluate_ShellSafe_DenyUnsafeCommand(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: deny
policies:
  - name: safe-shell
    tools: ["Bash"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: ["ls", "git"]
  - name: deny-all-shell
    tools: ["Bash"]
    action: deny
    message: "Unsafe command blocked"
`)

	cache := NewPolicyCache(path, false)
	resp, err := cache.Evaluate("Bash", map[string]interface{}{"command": "rm -rf /"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny for rm, got %q", resp.Decision)
	}
}

func TestEvaluate_ShellSafe_QuoteBypassBlocked(t *testing.T) {
	path := writePolicyFile(t, `
version: "1.0"
default_action: deny
policies:
  - name: safe-shell
    tools: ["Bash"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: ["ls", "git"]
  - name: deny-all-shell
    tools: ["Bash"]
    action: deny
    message: "Blocked"
`)

	cache := NewPolicyCache(path, false)
	// w'h'o'am'i resolves to whoami via AST — not in allowlist
	resp, _ := cache.Evaluate("Bash", map[string]interface{}{"command": "w'h'o'am'i"})
	if resp.Decision != "deny" {
		t.Errorf("expected deny for quote-bypass whoami, got %q", resp.Decision)
	}
}
