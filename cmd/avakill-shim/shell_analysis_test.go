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
	// Simple pipe without shell interpreter — safe in allowlist mode
	// but now pipes are checked only for shell interpreters (still safe in non-allowlist)
	safe, reason := isShellSafe("ls -la | grep foo", nil)
	if !safe {
		t.Errorf("expected safe for simple pipe, got unsafe: %s", reason)
	}
}

// --- Fix 1: ANSI-C quoting bypass tests ---

func TestIsShellSafe_ANSICQuoting_Unsafe(t *testing.T) {
	// $'\x72\x6d' is ANSI-C quoting for "rm" — must not resolve, must fail safe
	safe, _ := isShellSafe(`$'\x72\x6d' -rf /`, nil)
	if safe {
		t.Error("expected unsafe for ANSI-C quoted command (non-allowlist)")
	}
}

func TestIsShellSafe_ANSICQuoting_Allowlist(t *testing.T) {
	// $'\x6c\x73' is ANSI-C for "ls" — can't resolve, so not in allowlist
	safe, _ := isShellSafe(`$'\x6c\x73'`, []string{"ls", "cat"})
	if safe {
		t.Error("expected unsafe: ANSI-C quoted command can't be resolved to match allowlist")
	}
}

func TestAnalyzeCommand_ANSICQuoting_NoResolve(t *testing.T) {
	// ANSI-C quoting should not resolve to a base command
	a := analyzeCommand(`$'\x72\x6d' -rf /`)
	for _, cmd := range a.BaseCommands {
		if cmd == "rm" || cmd == `\x72\x6d` {
			t.Errorf("ANSI-C quoted command should not resolve, got %q in BaseCommands", cmd)
		}
	}
}

// --- Fix 2: Allowlist structural checks tests ---

func TestIsShellSafe_Allowlist_CommandSubstitution(t *testing.T) {
	safe, reason := isShellSafe("echo $(cat /etc/passwd)", []string{"echo", "cat"})
	if safe {
		t.Error("expected unsafe: command substitution should be blocked in allowlist mode")
	}
	if !strings.Contains(reason, "command substitution") {
		t.Errorf("expected reason about command substitution, got %q", reason)
	}
}

func TestIsShellSafe_Allowlist_ProcessSubstitution(t *testing.T) {
	safe, reason := isShellSafe("diff <(echo a) <(echo b)", []string{"diff", "echo"})
	if safe {
		t.Error("expected unsafe: process substitution should be blocked in allowlist mode")
	}
	if !strings.Contains(reason, "process substitution") {
		t.Errorf("expected reason about process substitution, got %q", reason)
	}
}

func TestIsShellSafe_Allowlist_Subshell(t *testing.T) {
	safe, reason := isShellSafe("(ls -la)", []string{"ls"})
	if safe {
		t.Error("expected unsafe: subshells should be blocked in allowlist mode")
	}
	if !strings.Contains(reason, "subshell") {
		t.Errorf("expected reason about subshells, got %q", reason)
	}
}

// --- Fix 3: Variable expansion in non-allowlist mode tests ---

func TestIsShellSafe_VariableExpansion_IFS(t *testing.T) {
	safe, reason := isShellSafe("cat${IFS}/etc/passwd", nil)
	if safe {
		t.Error("expected unsafe for IFS variable expansion bypass")
	}
	if !strings.Contains(reason, "variable expansion") {
		t.Errorf("expected reason about variable expansion, got %q", reason)
	}
}

func TestIsShellSafe_VariableExpansion_Target(t *testing.T) {
	safe, _ := isShellSafe("rm $TARGET", nil)
	if safe {
		t.Error("expected unsafe for variable expansion in arguments")
	}
}

// --- Fix 4: Glob/brace metacharacter tests ---

func TestIsShellSafe_GlobInCommandName(t *testing.T) {
	// /???/??t is a glob pattern that could match /bin/cat
	safe, reason := isShellSafe("/???/??t /???/p??s??", nil)
	if safe {
		t.Error("expected unsafe for glob metacharacters in command name")
	}
	if !strings.Contains(reason, "metacharacter") {
		t.Errorf("expected reason about metacharacters, got %q", reason)
	}
}

func TestIsShellSafe_BraceExpansion(t *testing.T) {
	// {cat,/etc/passwd} is brace expansion
	safe, reason := isShellSafe("{cat,/etc/passwd}", nil)
	if safe {
		t.Error("expected unsafe for brace expansion in command name")
	}
	if !strings.Contains(reason, "metacharacter") {
		t.Errorf("expected reason about metacharacters, got %q", reason)
	}
}

func TestIsShellSafe_WildcardInCommandName(t *testing.T) {
	safe, _ := isShellSafe("/bin/c*t /etc/passwd", nil)
	if safe {
		t.Error("expected unsafe for wildcard in command name")
	}
}

func TestIsShellSafe_BracketInCommandName(t *testing.T) {
	safe, _ := isShellSafe("/bin/[c]at /etc/passwd", nil)
	if safe {
		t.Error("expected unsafe for bracket glob in command name")
	}
}

// --- Fix 5: Redirect and background job tests ---

func TestIsShellSafe_Redirect_Unsafe(t *testing.T) {
	safe, reason := isShellSafe("echo secret > /tmp/exfil", nil)
	if safe {
		t.Error("expected unsafe for redirect in non-allowlist mode")
	}
	if !strings.Contains(reason, "redirect") {
		t.Errorf("expected reason about redirect, got %q", reason)
	}
}

func TestIsShellSafe_BackgroundJob_Unsafe(t *testing.T) {
	safe, reason := isShellSafe("sleep 100 &", nil)
	if safe {
		t.Error("expected unsafe for background job in non-allowlist mode")
	}
	if !strings.Contains(reason, "background") {
		t.Errorf("expected reason about background job, got %q", reason)
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
