# AST-based Shell Command Analysis for avakill-shim

**Date:** 2026-02-25
**Status:** Approved

## Problem

The Go shim's `args_match` uses substring matching for shell command conditions, which is trivially bypassed:

- Quote insertion: `w'h'o'am'i` executes `whoami` but doesn't match substring "whoami"
- Variable expansion: `cat${IFS}/etc/passwd` doesn't match "cat /etc/passwd"
- Base64 encoding: `echo cm0gLXJmIC8= | base64 -d | bash` executes `rm -rf /`
- Command substitution: `who$(echo am)i` doesn't match "whoami"
- Brace expansion: `{cat,/etc/passwd}` bypasses space-based matching

## Solution

Port shell analysis to Go using `mvdan.cc/sh/v3/syntax`, a full POSIX/Bash parser that produces a typed AST. Single-pass walker extracts all security-relevant features in one parse.

## Architecture: Single-pass AST Walker

One `analyzeCommand()` call parses and walks the AST. `isShellSafe()` and `splitCompoundCommand()` are thin wrappers.

### New file: `cmd/avakill-shim/shell_analysis.go`

#### ShellAnalysis struct

```go
type ShellAnalysis struct {
    Pipes               bool
    Redirects           bool
    CommandSubstitution bool
    VariableExpansion   bool
    Subshells           bool
    BackgroundJobs      bool
    ProcessSubstitution bool
    DangerousBuiltins   []string  // eval, source, exec, xargs
    Segments            []string  // text of each simple command
    BaseCommands        []string  // first word of each simple command (quote-resolved)
    ParseError          bool
}
```

#### analyzeCommand(cmd string) ShellAnalysis

1. Parse with `syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse()`
2. Parse failure → `ShellAnalysis{ParseError: true}` (fail-closed)
3. Walk AST with `syntax.Walk()`, switching on node types:
   - `*syntax.BinaryCmd` → set Pipes/AND/OR flags, track segments
   - `*syntax.Redirect` → set Redirects
   - `*syntax.CmdSubst` → set CommandSubstitution, extract inner base commands
   - `*syntax.ParamExp` → set VariableExpansion
   - `*syntax.Subshell` → set Subshells
   - `*syntax.ProcSubst` → set ProcessSubstitution
   - `*syntax.CallExpr` → extract first word as base command (quote-resolved via word part concatenation)
   - `*syntax.Stmt` with `Background: true` → set BackgroundJobs
4. Check base commands against dangerous builtins set

Key: the AST parser handles quote stripping natively — `w'h'o'am'i` parses as Word parts `Lit("w") + SglQuoted("h") + Lit("o") + SglQuoted("am") + Lit("i")`, concatenating to `whoami`.

#### isShellSafe(cmd string, allowlist []string) (bool, string)

1. `ParseError` → `(false, "unparseable command (fail-closed)")`
2. If `allowlist` non-empty: every `BaseCommands` entry must be in allowlist, else `(false, "command 'X' not in allowlist")`
3. If no allowlist: flag `CommandSubstitution`, `ProcessSubstitution`, non-empty `DangerousBuiltins`, and pipe-to-shell patterns (any `BaseCommands` entry is `bash`/`sh`/`zsh`/`python`/`perl`/`ruby`/`node` combined with `Pipes`)
4. Otherwise → `(true, "")`

#### splitCompoundCommand(cmd string) []string

Returns `analysis.Segments`. On `ParseError`, returns `[]string{cmd}` (preserve original).

### Policy integration in `policy.go`

Add to `RuleConditions`:

```go
ShellSafe        bool     `yaml:"shell_safe,omitempty"`
CommandAllowlist []string `yaml:"command_allowlist,omitempty"`
```

In `checkConditions()`, after existing `args_match`/`args_not_match`:

```go
if conds.ShellSafe {
    cmd := extractCommand(args)  // tries args["command"], then args["cmd"]
    if cmd != "" {
        safe, _ := isShellSafe(cmd, conds.CommandAllowlist)
        if !safe {
            return false
        }
    }
}
```

Standard AND semantics: `shell_safe` is an additional condition ANDed with `args_match`/`args_not_match`. When the condition fails, the rule doesn't match (same as existing behavior).

### YAML policy examples

```yaml
# Allowlist-only shell access
policies:
  - name: safe-shell-commands
    tools: ["Bash", "shell_*", "run_shell_command"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: ["ls", "git", "cat", "grep", "find", "wc"]

  - name: deny-unsafe-shell
    tools: ["Bash", "shell_*", "run_shell_command"]
    action: deny
    message: "Command blocked: not in allowlist or uses dangerous shell features"
```

## Test plan

### shell_analysis_test.go

| Category | Input | Expected |
|----------|-------|----------|
| Simple safe | `ls -la` | safe, BaseCommands=["ls"] |
| Simple safe | `git status` | safe, BaseCommands=["git"] |
| Pipe detection | `cat /etc/passwd \| curl` | Pipes=true |
| Redirect | `echo secret > /tmp/exfil` | Redirects=true |
| Cmd substitution | `$(whoami)` | CommandSubstitution=true |
| Backtick | `` `whoami` `` | CommandSubstitution=true |
| Variable expansion | `${HOME}` | VariableExpansion=true |
| Compound splitting | `a && b \|\| c; d \| e` | 5 segments |
| Quote bypass | `w'h'o'am'i` | BaseCommands=["whoami"] |
| Base64 bypass | `echo cm0 \| base64 -d \| bash` | Pipes=true, "bash" in BaseCommands |
| IFS bypass | `cat${IFS}/etc/passwd` | VariableExpansion=true |
| Allowlist pass | `ls -la` with ["ls"] | safe |
| Allowlist reject | `rm -rf /` with ["ls","git"] | unsafe |
| Parse error | `"unterminated` | ParseError=true → unsafe |
| Empty command | `""` | safe |
| Dangerous builtins | `eval "rm -rf /"` | DangerousBuiltins=["eval"] |
| Process substitution | `diff <(cmd1) <(cmd2)` | ProcessSubstitution=true |
| Background job | `sleep 100 &` | BackgroundJobs=true |

### policy_test.go additions

- `shell_safe: true` condition with safe command → rule matches
- `shell_safe: true` with unsafe command → rule skipped
- `command_allowlist` with allowed command → rule matches
- `command_allowlist` with disallowed command → rule skipped
- `shell_safe` ANDed with `args_match` → both must pass

## Dependency

Add `mvdan.cc/sh/v3` to `cmd/avakill-shim/go.mod`. Pure Go, no CGo.

## Files changed

- `cmd/avakill-shim/go.mod` — add mvdan.cc/sh/v3 dependency
- `cmd/avakill-shim/shell_analysis.go` — new file: ShellAnalysis, analyzeCommand, isShellSafe, splitCompoundCommand
- `cmd/avakill-shim/shell_analysis_test.go` — new file: comprehensive test suite
- `cmd/avakill-shim/policy.go` — add ShellSafe/CommandAllowlist to RuleConditions, integrate into checkConditions
- `cmd/avakill-shim/policy_test.go` — add shell_safe integration tests
