package main

import (
	"strings"
	"testing"
)

func TestAnalyzeCommand_SimpleCommand(t *testing.T) {
	a := analyzeCommand("ls -la")
	if a.ParseError {
		t.Fatal("unexpected parse error")
	}
	if len(a.BaseCommands) != 1 || a.BaseCommands[0] != "ls" {
		t.Errorf("expected BaseCommands=[ls], got %v", a.BaseCommands)
	}
	if a.Pipes || a.Redirects || a.CommandSubstitution || a.VariableExpansion {
		t.Error("simple command should have no flags set")
	}
}

func TestAnalyzeCommand_Pipe(t *testing.T) {
	a := analyzeCommand("cat /etc/passwd | grep root")
	if !a.Pipes {
		t.Error("expected Pipes=true")
	}
	if len(a.BaseCommands) < 2 {
		t.Fatalf("expected 2+ base commands, got %v", a.BaseCommands)
	}
	if a.BaseCommands[0] != "cat" || a.BaseCommands[1] != "grep" {
		t.Errorf("expected [cat, grep], got %v", a.BaseCommands)
	}
}

func TestAnalyzeCommand_Redirect(t *testing.T) {
	a := analyzeCommand("echo secret > /tmp/exfil")
	if !a.Redirects {
		t.Error("expected Redirects=true")
	}
}

func TestAnalyzeCommand_CommandSubstitution_Dollar(t *testing.T) {
	a := analyzeCommand("echo $(whoami)")
	if !a.CommandSubstitution {
		t.Error("expected CommandSubstitution=true for $()")
	}
}

func TestAnalyzeCommand_CommandSubstitution_Backtick(t *testing.T) {
	a := analyzeCommand("echo `whoami`")
	if !a.CommandSubstitution {
		t.Error("expected CommandSubstitution=true for backticks")
	}
}

func TestAnalyzeCommand_VariableExpansion_Braces(t *testing.T) {
	a := analyzeCommand("echo ${HOME}")
	if !a.VariableExpansion {
		t.Error("expected VariableExpansion=true for ${}")
	}
}

func TestAnalyzeCommand_VariableExpansion_Short(t *testing.T) {
	a := analyzeCommand("echo $PATH")
	if !a.VariableExpansion {
		t.Error("expected VariableExpansion=true for $VAR")
	}
}

func TestAnalyzeCommand_Subshell(t *testing.T) {
	a := analyzeCommand("(cd /tmp && ls)")
	if !a.Subshells {
		t.Error("expected Subshells=true")
	}
}

func TestAnalyzeCommand_BackgroundJob(t *testing.T) {
	a := analyzeCommand("sleep 100 &")
	if !a.BackgroundJobs {
		t.Error("expected BackgroundJobs=true")
	}
}

func TestAnalyzeCommand_ProcessSubstitution(t *testing.T) {
	a := analyzeCommand("diff <(echo a) <(echo b)")
	if !a.ProcessSubstitution {
		t.Error("expected ProcessSubstitution=true")
	}
}

func TestAnalyzeCommand_QuoteBypass(t *testing.T) {
	a := analyzeCommand("w'h'o'am'i")
	found := false
	for _, cmd := range a.BaseCommands {
		if cmd == "whoami" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected whoami in BaseCommands after quote resolution, got %v", a.BaseCommands)
	}
}

func TestAnalyzeCommand_IFSBypass(t *testing.T) {
	a := analyzeCommand("cat${IFS}/etc/passwd")
	if !a.VariableExpansion {
		t.Error("expected VariableExpansion=true for ${IFS}")
	}
}

func TestAnalyzeCommand_CompoundCommand(t *testing.T) {
	a := analyzeCommand("cmd1 && cmd2 || cmd3; cmd4 | cmd5")
	if len(a.Segments) != 5 {
		t.Errorf("expected 5 segments, got %d: %v", len(a.Segments), a.Segments)
	}
}

func TestAnalyzeCommand_DangerousBuiltin_Eval(t *testing.T) {
	a := analyzeCommand(`eval "rm -rf /"`)
	found := false
	for _, b := range a.DangerousBuiltins {
		if b == "eval" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected eval in DangerousBuiltins, got %v", a.DangerousBuiltins)
	}
}

func TestAnalyzeCommand_ParseError(t *testing.T) {
	a := analyzeCommand(`"unterminated`)
	if !a.ParseError {
		t.Error("expected ParseError=true for unterminated quote")
	}
}

func TestAnalyzeCommand_Empty(t *testing.T) {
	a := analyzeCommand("")
	if a.ParseError {
		t.Error("empty command should not be a parse error")
	}
	if len(a.BaseCommands) != 0 {
		t.Errorf("expected no base commands, got %v", a.BaseCommands)
	}
}

func TestAnalyzeCommand_Base64PipeToShell(t *testing.T) {
	a := analyzeCommand("echo cm0gLXJmIC8= | base64 -d | bash")
	if !a.Pipes {
		t.Error("expected Pipes=true")
	}
	foundBash := false
	for _, cmd := range a.BaseCommands {
		if cmd == "bash" {
			foundBash = true
			break
		}
	}
	if !foundBash {
		t.Errorf("expected bash in BaseCommands, got %v", a.BaseCommands)
	}
}

// --- isShellSafe tests ---

func TestIsShellSafe_SimpleCommand(t *testing.T) {
	safe, reason := isShellSafe("ls -la", nil)
	if !safe {
		t.Errorf("expected safe, got unsafe: %s", reason)
	}
}

func TestIsShellSafe_GitStatus(t *testing.T) {
	safe, reason := isShellSafe("git status", nil)
	if !safe {
		t.Errorf("expected safe, got unsafe: %s", reason)
	}
}

func TestIsShellSafe_CommandSubstitution(t *testing.T) {
	safe, _ := isShellSafe("echo $(whoami)", nil)
	if safe {
		t.Error("expected unsafe for command substitution")
	}
}

func TestIsShellSafe_ProcessSubstitution(t *testing.T) {
	safe, _ := isShellSafe("diff <(echo a) <(echo b)", nil)
	if safe {
		t.Error("expected unsafe for process substitution")
	}
}

func TestIsShellSafe_DangerousBuiltin(t *testing.T) {
	safe, reason := isShellSafe(`eval "rm -rf /"`, nil)
	if safe {
		t.Error("expected unsafe for eval")
	}
	if !strings.Contains(reason, "eval") {
		t.Errorf("expected reason to mention eval, got %q", reason)
	}
}

func TestIsShellSafe_PipeToShell(t *testing.T) {
	safe, _ := isShellSafe("echo cm0gLXJmIC8= | base64 -d | bash", nil)
	if safe {
		t.Error("expected unsafe for pipe to bash")
	}
}

func TestIsShellSafe_SimplePipe(t *testing.T) {
	// Simple pipe without shell interpreter should be safe (no allowlist mode)
	safe, reason := isShellSafe("ls -la | grep foo", nil)
	if !safe {
		t.Errorf("expected safe for simple pipe, got unsafe: %s", reason)
	}
}

func TestIsShellSafe_ParseError(t *testing.T) {
	safe, _ := isShellSafe(`"unterminated`, nil)
	if safe {
		t.Error("expected unsafe for parse error (fail-closed)")
	}
}

func TestIsShellSafe_Empty(t *testing.T) {
	safe, _ := isShellSafe("", nil)
	if !safe {
		t.Error("expected safe for empty command")
	}
}

func TestIsShellSafe_Allowlist_Pass(t *testing.T) {
	safe, _ := isShellSafe("ls -la", []string{"ls", "git", "cat"})
	if !safe {
		t.Error("expected safe when command is in allowlist")
	}
}

func TestIsShellSafe_Allowlist_Reject(t *testing.T) {
	safe, reason := isShellSafe("rm -rf /", []string{"ls", "git", "cat"})
	if safe {
		t.Error("expected unsafe when command not in allowlist")
	}
	if !strings.Contains(reason, "rm") && !strings.Contains(reason, "allowlist") {
		t.Errorf("expected reason about rm/allowlist, got %q", reason)
	}
}

func TestIsShellSafe_Allowlist_CompoundReject(t *testing.T) {
	// All commands in a compound must be in the allowlist
	safe, _ := isShellSafe("ls -la && rm -rf /", []string{"ls", "git"})
	if safe {
		t.Error("expected unsafe when any command not in allowlist")
	}
}

func TestIsShellSafe_Allowlist_CompoundPass(t *testing.T) {
	safe, _ := isShellSafe("ls -la && git status", []string{"ls", "git"})
	if !safe {
		t.Error("expected safe when all commands in allowlist")
	}
}

// --- splitCompoundCommand tests ---

func TestSplitCompoundCommand_Simple(t *testing.T) {
	segments := splitCompoundCommand("ls -la")
	if len(segments) != 1 {
		t.Errorf("expected 1 segment, got %d: %v", len(segments), segments)
	}
}

func TestSplitCompoundCommand_AndOr(t *testing.T) {
	segments := splitCompoundCommand("cmd1 && cmd2 || cmd3")
	if len(segments) != 3 {
		t.Errorf("expected 3 segments, got %d: %v", len(segments), segments)
	}
}

func TestSplitCompoundCommand_Semicolon(t *testing.T) {
	segments := splitCompoundCommand("cmd1; cmd2")
	if len(segments) != 2 {
		t.Errorf("expected 2 segments, got %d: %v", len(segments), segments)
	}
}

func TestSplitCompoundCommand_Pipe(t *testing.T) {
	segments := splitCompoundCommand("cat file | grep foo | wc -l")
	// Pipe segments: cat file, grep foo, wc -l
	if len(segments) < 3 {
		t.Errorf("expected 3+ segments for pipe, got %d: %v", len(segments), segments)
	}
}

func TestSplitCompoundCommand_ParseError(t *testing.T) {
	segments := splitCompoundCommand(`"unterminated`)
	// On parse error, return the original command as a single segment
	if len(segments) != 1 {
		t.Errorf("expected 1 segment on parse error, got %d: %v", len(segments), segments)
	}
}

func TestSplitCompoundCommand_Empty(t *testing.T) {
	segments := splitCompoundCommand("")
	if len(segments) != 0 {
		t.Errorf("expected 0 segments for empty, got %d", len(segments))
	}
}
