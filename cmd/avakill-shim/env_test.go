package main

import (
	"strings"
	"testing"
)

func TestParseEnv(t *testing.T) {
	input := "HOME=/Users/test\nPATH=/usr/bin:/usr/local/bin\nSHELL=/bin/zsh\n"
	env := parseEnv(input)

	if env["HOME"] != "/Users/test" {
		t.Errorf("expected HOME=/Users/test, got %q", env["HOME"])
	}
	if env["PATH"] != "/usr/bin:/usr/local/bin" {
		t.Errorf("expected PATH=/usr/bin:/usr/local/bin, got %q", env["PATH"])
	}
	if env["SHELL"] != "/bin/zsh" {
		t.Errorf("expected SHELL=/bin/zsh, got %q", env["SHELL"])
	}
}

func TestParseEnvWithEquals(t *testing.T) {
	// Values can contain = signs
	input := "FOO=bar=baz\nBAR=a==b\n"
	env := parseEnv(input)

	if env["FOO"] != "bar=baz" {
		t.Errorf("expected FOO=bar=baz, got %q", env["FOO"])
	}
	if env["BAR"] != "a==b" {
		t.Errorf("expected BAR=a==b, got %q", env["BAR"])
	}
}

func TestParseEnvSkipsInvalid(t *testing.T) {
	input := "VALID=yes\n=nope\njusttext\n\n"
	env := parseEnv(input)

	if env["VALID"] != "yes" {
		t.Errorf("expected VALID=yes, got %q", env["VALID"])
	}
	if len(env) != 1 {
		t.Errorf("expected 1 entry, got %d", len(env))
	}
}

func TestParseEnvEmpty(t *testing.T) {
	env := parseEnv("")
	if len(env) != 0 {
		t.Errorf("expected empty map, got %d entries", len(env))
	}
}

func TestEnvToSlice(t *testing.T) {
	env := map[string]string{
		"HOME": "/Users/test",
		"PATH": "/usr/bin",
	}

	slice := EnvToSlice(env)
	if len(slice) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(slice))
	}

	found := map[string]bool{}
	for _, s := range slice {
		found[s] = true
	}
	if !found["HOME=/Users/test"] {
		t.Error("missing HOME=/Users/test")
	}
	if !found["PATH=/usr/bin"] {
		t.Error("missing PATH=/usr/bin")
	}
}

func TestRecoverShellEnv(t *testing.T) {
	// Reset cache so we get a fresh recovery
	ResetEnvCache()

	env, err := RecoverShellEnv()
	if err != nil {
		t.Skipf("shell env recovery not available: %v", err)
	}

	// Should have at least PATH and HOME
	if _, ok := env["PATH"]; !ok {
		t.Error("recovered env missing PATH")
	}
	if _, ok := env["HOME"]; !ok {
		t.Error("recovered env missing HOME")
	}
}

func TestRecoverShellEnvCached(t *testing.T) {
	ResetEnvCache()

	env1, err := RecoverShellEnv()
	if err != nil {
		t.Skipf("shell env recovery not available: %v", err)
	}

	env2, err := RecoverShellEnv()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// Should be the same map (cached)
	if len(env1) != len(env2) {
		t.Error("cached env has different length")
	}
}

func TestResolveInEnv(t *testing.T) {
	ResetEnvCache()

	// "ls" should be findable in any environment
	path, err := ResolveInEnv("ls")
	if err != nil {
		t.Fatalf("failed to resolve 'ls': %v", err)
	}
	if !strings.Contains(path, "ls") {
		t.Errorf("resolved path doesn't contain 'ls': %q", path)
	}
}

func TestResolveInEnvNotFound(t *testing.T) {
	ResetEnvCache()

	_, err := ResolveInEnv("nonexistent-binary-that-does-not-exist-xyz123")
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
}
