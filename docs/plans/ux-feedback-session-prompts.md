# AvaKill UX Feedback — Session Prompts

Generated from beta tester feedback (Feb 2026). Each prompt is designed for a fresh Claude Code session in the `/Users/ablecoffee/avakill` project.

---

## Session 1: Quick Wins (1 session, ~15 min)

```
AvaKill UX fixes — 3 quick wins from beta tester feedback. Do all three in this session.

### Fix 1: Make `avakill launch` fail loudly on macOS

**Problem**: `avakill launch` silently does nothing on macOS. It prints "platform: unsupported, sandbox_applied: False" but no error, no suggestion, no fallback. Users think they're protected when they're not. Meanwhile `avakill enforce sandbox` DOES generate a working macOS sandbox-exec profile — but the two features are unaware of each other.

**Files**:
- CLI command: `src/avakill/cli/launch_cmd.py` (function `launch()`, lines 17-122)
- Core launcher: `src/avakill/launcher/core.py` (class `ProcessLauncher`)
- Tests: `tests/test_cli_launch.py`

**What to do**: When the platform is `darwin` and no sandbox backend is available, `avakill launch` should:
1. Exit with a non-zero code
2. Print a clear error: "macOS does not support `avakill launch` directly. Use `avakill enforce sandbox` to generate a sandbox-exec profile, then run: `sandbox-exec -f <profile> <command>`"
3. Add a test that verifies this behavior on darwin

---

### Fix 2: Document match semantics in schema output

**Problem**: The tester was confused about whether a rule with `tools: ["all"]` and `conditions: args_match: ...` would block ALL calls (even non-matching conditions) or fall through. It correctly falls through — but this isn't documented. The schema says "first match wins" but doesn't clarify that "match" means BOTH tool pattern AND conditions.

**Files**:
- Schema generator: `src/avakill/schema.py` (function `generate_prompt()`, lines 103-212)
- Policy engine (reference): `src/avakill/core/policy.py` (method `evaluate()`, lines 175-253)

**What to do**: In the `generate_prompt()` function, add a clear note in the evaluation rules section:
> "A rule matches only when BOTH the tool pattern AND all conditions are satisfied. If a tool matches the pattern but conditions are not met, evaluation continues to the next rule."

This should appear near the existing "first match wins" explanation. Don't change any logic — just the documentation string.

---

### Fix 3: Clarify soft vs advisory enforcement in schema

**Problem**: The tester couldn't understand how `enforcement: soft` differs from `enforcement: advisory` in practice. Soft says "overridable with audit trail" but doesn't explain the override mechanism. Advisory says "logs but always allows."

**Files**:
- Schema generator: `src/avakill/schema.py` (function `generate_prompt()`)
- Model definition: `src/avakill/core/models.py` (class `PolicyRule`, lines 167-173)
- Enforcement logic: `src/avakill/core/policy.py` (`evaluate()`, lines 217-233)
- Override handling: `src/avakill/core/engine.py` (`Guard.evaluate()`, lines 290-298)

**What to do**: In the schema prompt output, expand the enforcement level descriptions:
- **hard** (default): "Denied calls are blocked. Cannot be overridden."
- **soft**: "Denied calls are blocked by default but can be overridden by passing `override=True` to `Guard.evaluate()`. The override is logged in the audit trail. Use this for rules where a human or senior agent should be able to approve exceptions."
- **advisory**: "The rule is evaluated and logged, but the call is always allowed regardless of the action. Use this for monitoring and visibility without enforcement."

---

### Verification

After all three fixes:
1. `make check` passes (lint + typecheck + tests)
2. `.venv/bin/avakill schema --format=prompt` output includes the new match semantics note and expanded enforcement descriptions
3. `tests/test_cli_launch.py` has a new test for the macOS error message
```

---

## Session 2: Medium — Validate Shadow Warnings + Simulate Burst (1 session)

```
AvaKill feature: Add two related features that improve the policy debugging feedback loop.

### Feature 1: `avakill validate` warns about shadowed rules

**Problem**: A beta tester wrote a rule with `tools: ["file_*"]` for a "throttle writes" rule. Because `file_*` matches `file_read`, `file_delete`, AND `file_write`, it accidentally shadowed a later `allow-reads-with-logging` rule for `file_read` calls. They only caught this because they manually tested with `avakill evaluate`. The `validate` command should catch this automatically.

**Files**:
- Validate command: `src/avakill/cli/validate_cmd.py` (function `validate()`, lines 20-139)
- PolicyEngine: `src/avakill/core/policy.py` (method `_match_tool()`, lines 255-273 — uses fnmatch)
- Tests: `tests/test_cli.py` (existing validate tests)

**What to do**:
1. After successful validation, analyze rules for shadow conflicts:
   - For each rule R at index i, check if any later rule R' at index j>i has a tool pattern that is a subset of R's tool pattern (i.e., any tool matching R' would also match R)
   - Use `fnmatch` to test a reasonable set of common tool names or compare glob patterns
   - Generate warnings like: "Warning: Rule 3 'block-all-writes' (tools: file_*) shadows Rule 7 'allow-reads' (tools: file_read) — file_read matches both patterns. Rule 7 may be unreachable for file_read calls."
2. Warnings should NOT cause validate to fail — they're informational
3. Only warn when the shadowed rule has a DIFFERENT action than the shadowing rule (same action = no real conflict)
4. Print warnings using Rich with `[yellow]Warning[/yellow]` styling
5. Add tests covering: shadow detected, no shadow when actions match, no shadow when patterns don't overlap

**Implementation approach**: Extract the tool names from each rule's `tools` list. For glob patterns (containing `*` or `?`), expand them against the tool names used in ALL other rules to detect overlaps. A rule R shadows R' if: (a) R appears before R', (b) at least one tool in R' also matches R's pattern, and (c) R and R' have different actions.

---

### Feature 2: `avakill evaluate --simulate-burst N`

**Problem**: The tester has a rate-limited rule (`rate_limit: { max_calls: 20, window: "1m" }`) but `evaluate` only tests one call at a time. There's no way to verify rate limiting works without a real agent hitting the limit.

**Files**:
- Evaluate command: `src/avakill/cli/evaluate_cmd.py` (function `evaluate()`, lines 25-79, `_evaluate_standalone()` lines 82-105)
- Guard: `src/avakill/core/engine.py` (method `Guard.evaluate()`)
- PolicyEngine rate limit: `src/avakill/core/policy.py` (method `_check_rate_limit()`, lines 323-349)
- Tests: `tests/test_cli.py` (existing evaluate tests)

**What to do**:
1. Add `--simulate-burst N` option to the `evaluate` command (only works with `--policy` standalone mode)
2. When specified, simulate N rapid calls to the same tool with the same args
3. Output a summary showing:
   - Call 1-N: allowed/denied
   - At which call number the rate limit triggered (if applicable)
   - Example: "Calls 1-20: ALLOW (rule: throttle-writes) | Call 21: DENY (rate limit exceeded: 20/1m)"
4. If no rate limit exists on the matched rule, just say "All N calls: ALLOW (no rate limit on matched rule)"
5. Add tests for burst simulation with and without rate limits

---

### Verification

1. `make check` passes
2. Create a test policy with a shadowing issue and verify `avakill validate` prints the warning
3. Create a test policy with a rate-limited rule and verify `avakill evaluate --simulate-burst 25 --policy test.yaml --tool file_write --args '{}'` shows the rate limit trigger point
```

---

## Session 3: Medium — Batch Policy Test Runner (1 session)

```
AvaKill feature: Add `avakill test` command for batch policy testing.

**Problem**: After editing a policy, the beta tester had to manually re-run `avakill evaluate` 11 times with different tool/args combinations to verify their policy behaved correctly. There should be a way to define test cases in a file and run them all at once.

**Files to read first**:
- Evaluate command (reference): `src/avakill/cli/evaluate_cmd.py`
- CLI registration: `src/avakill/cli/main.py` (lazy command loading)
- Guard: `src/avakill/core/engine.py`
- PolicyEngine: `src/avakill/core/policy.py`
- Existing CLI tests: `tests/test_cli.py`

**What to build**:

1. New CLI command: `avakill test <policy.yaml> <tests.json>`
2. Test file format (JSON):
```json
{
  "tests": [
    {
      "name": "block rm -rf",
      "tool": "shell_exec",
      "args": {"command": "rm -rf /"},
      "expect": "deny"
    },
    {
      "name": "allow git status",
      "tool": "shell_exec",
      "args": {"command": "git status"},
      "expect": "allow"
    },
    {
      "name": "block env file reads",
      "tool": "file_read",
      "args": {"file_path": "/app/.env"},
      "expect": "deny",
      "expect_rule": "block-secrets"
    }
  ]
}
```

3. Each test case has:
   - `name` (required): human-readable description
   - `tool` (required): tool name to evaluate
   - `args` (required): dict of arguments
   - `expect` (required): "allow" or "deny"
   - `expect_rule` (optional): expected matching rule name

4. Output: Rich table showing pass/fail for each test case:
   ```
   Policy: policy.yaml | Tests: tests.json
   ──────────────────────────────────────────────────────
    #  Name                  Expected  Got     Rule            Result
    1  block rm -rf          deny      deny    block-shell     PASS
    2  allow git status      allow     allow   safe-shell      PASS
    3  block env file reads  deny      allow   allow-reads     FAIL
   ──────────────────────────────────────────────────────
   Results: 2 passed, 1 failed
   ```

5. Exit code: 0 if all pass, 1 if any fail
6. Also support YAML format for the test file (detect by extension)

**Implementation**:
- New file: `src/avakill/cli/test_cmd.py`
- Register in `src/avakill/cli/main.py` lazy command map
- Use `Guard` with standalone `PolicyEngine.from_yaml()` (no daemon needed)
- Use Rich `Table` for output (consistent with validate command style)
- Add tests in `tests/test_cli_test_cmd.py`

**Verification**:
1. `make check` passes
2. Create a sample policy and test file, run `avakill test sample-policy.yaml sample-tests.json` and verify output
3. `avakill test --help` shows usage
```

---

## Session 4: Medium — Quickstart + Init Scan (1 session)

```
AvaKill feature: Improve first-time onboarding with `avakill quickstart` and `avakill init --scan`.

**Problem**: There's no single "do this first" flow. The beta tester had to piece together init → schema → write file → validate → review → approve by trial and error. Also, `avakill init` generates a generic policy with no awareness of the current project.

**Files to read first**:
- Init command: `src/avakill/cli/init_cmd.py` (function `init()`, lines 116-268)
- Framework detection: `src/avakill/cli/init_cmd.py` (`_detect_frameworks()`, lines 60-87)
- CLI registration: `src/avakill/cli/main.py`
- Policy templates: `src/avakill/templates/` (look at existing .yaml templates)
- Hook installer: `src/avakill/hooks/installer.py` (functions `detect_agents()`, `install_hook()`)
- Existing init tests: `tests/test_cli_init.py`

### Feature 1: `avakill init --scan`

Enhance the existing `init` command with a `--scan` flag that introspects the current project directory:

1. **Detect sensitive files**: Scan for common secret/config patterns:
   - `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.keystore`
   - `credentials.json`, `serviceAccountKey.json`, `secrets.yaml`
   - `.aws/`, `.ssh/`, `.gnupg/`
   - `*.sqlite`, `*.db` (database files)
2. **Detect project type**: Look for language/framework indicators:
   - `package.json` → Node.js (add npm/yarn-specific rules)
   - `pyproject.toml`/`setup.py` → Python
   - `Cargo.toml` → Rust
   - `go.mod` → Go
   - `*.xcodeproj`/`Package.swift` → Swift/iOS
   - `Dockerfile`/`docker-compose.yml` → containerized
3. **Generate targeted deny rules**: For each detected sensitive file, add a deny rule:
   ```yaml
   - name: protect-env-files
     tools: ["file_write", "file_delete"]
     action: deny
     conditions:
       args_match:
         file_path: [".env"]
     message: "Detected .env file — blocking write/delete by default"
   ```
4. Print a summary of what was detected before generating the policy
5. The generated policy should be written to the same location as normal `init` (the `avakill.yaml` path)

### Feature 2: `avakill quickstart`

A new guided command that chains the full setup flow:

1. **Detect agents**: Call `detect_agents()` from `src/avakill/hooks/installer.py` to find installed AI agents
2. **Ask 3 questions** (use Click prompts):
   - "Which agent do you want to guard?" (show detected agents, allow "all")
   - "What protection level?" (strict / moderate / permissive — maps to existing templates)
   - "Scan this directory for sensitive files?" (yes/no — runs the --scan logic)
3. **Generate policy**: Combine template + scan results → write `avakill.yaml`
4. **Validate**: Auto-run `avakill validate` on the generated file
5. **Install hook**: If an agent was selected, auto-run the hook installation
6. **Print next steps**: Show the user what to do next (review, approve, test)

Output should look like:
```
AvaKill Quickstart
─────────────────────────────
Detected agents: claude-code, cursor
Detected sensitive files: .env, .env.local, credentials.json

✓ Policy generated: avakill.yaml (12 rules)
✓ Validation passed
✓ Hook installed for claude-code

Next steps:
  1. Review your policy:  avakill review
  2. Test a tool call:    avakill evaluate --policy avakill.yaml --tool shell_exec --args '{"command": "rm -rf /"}'
  3. Approve the policy:  avakill approve avakill.yaml
```

**Implementation**:
- Enhance `src/avakill/cli/init_cmd.py` with `--scan` flag and scanning logic
- New file: `src/avakill/cli/quickstart_cmd.py`
- Register `quickstart` in `src/avakill/cli/main.py`
- Add tests for both features

**Verification**:
1. `make check` passes
2. In a test directory with a `.env` file, `avakill init --scan` generates rules that block `.env` writes
3. `avakill quickstart --help` shows usage
```

---

## Session 5: Large — Fix macOS Sandbox Profile Generator (1 session)

```
AvaKill bug fix: The `.sb` sandbox profile generator (`avakill enforce sandbox`) produces unusably broad profiles.

**Problem**: The generated sandbox-exec profile translates deny rules into blanket operations with no path scoping:
```
(deny file-write-data)
(deny process-exec)
(deny network-outbound)
```
This blocks the agent process from even starting. The policy YAML has a `sandbox:` section with `allow_paths` containing read/write/execute paths — but the `.sb` generator ignores it entirely. It only looks at the deny rules.

The beta tester had to throw away the generated file and manually write a proper sandbox-exec profile with `(subpath "/Users/ablecoffee/Pane")` scoping.

**Files to read first**:
- Generator: `src/avakill/enforcement/sandbox_exec.py` (class `SandboxExecEnforcer`, method `generate_profile()`, lines 59-99)
- CLI command: `src/avakill/cli/enforce_cmd.py` (function `sandbox()`, lines 72-100)
- Policy models: `src/avakill/core/models.py` (look for `sandbox` section in `PolicyConfig`)
- Tests: `tests/test_cli_enforce.py`
- Also check `src/avakill/enforcement/` for other enforcer patterns (Landlock etc.) for reference

**What needs to change in `generate_profile()`**:

1. **Start with `(allow default)`** instead of deny-all. The profile should be permissive by default and deny specific paths/operations.

2. **Use `allow_paths` from the policy's `sandbox:` section** to scope denials:
   ```scheme
   ;; Allow reads everywhere, deny writes except to allowed paths
   (deny file-write* (subpath "/")
     (require-not
       (subpath "/Users/ablecoffee/project/output")
       (subpath "/tmp")))
   ```

3. **Never globally deny `process-exec`** — this bricks the wrapped command. Instead:
   - If specific commands should be blocked, use `(deny process-exec (literal "/usr/bin/rm"))` etc.
   - If the policy just says "deny shell_exec", translate that to denying known shell paths (`/bin/sh`, `/bin/bash`, `/bin/zsh`) but always allow the target command.

4. **Map policy deny rules to scoped SBPL operations**:
   - `file_write` deny → `(deny file-write* (subpath "..."))` scoped to specific paths from `args_match`
   - `file_delete` deny → `(deny file-write-unlink (subpath "..."))` scoped
   - `network_*` deny → `(deny network-outbound (remote tcp "*:80"))` etc.
   - `shell_exec` deny with `args_match` → `(deny process-exec (literal "/path/to/blocked"))` for specific commands

5. **Add `--dry-run`** behavior that prints the generated profile to stdout without writing (may already exist — check)

6. **Add a safety check**: If the generated profile would deny `process-exec` globally, refuse to generate and print an error explaining why.

**Reference for macOS SBPL syntax** (what the generated output should look like):
```scheme
(version 1)
(allow default)

;; Block writes outside project directory
(deny file-write*
  (require-not
    (subpath "/Users/ablecoffee/project")
    (subpath "/tmp")
    (subpath "/private/var/folders")))

;; Block network access to non-allowed hosts
(deny network-outbound
  (require-not
    (remote tcp "localhost:*")
    (remote tcp "api.anthropic.com:443")))

;; Block execution of destructive commands
(deny process-exec
  (literal "/bin/rm")
  (literal "/usr/bin/killall"))
```

**Tests to add**:
- Profile uses `(allow default)` base
- `allow_paths` from sandbox section appear as exceptions in deny rules
- No global `(deny process-exec)` without path scoping
- Profile with only file deny rules doesn't touch network or process operations
- Round-trip: generate profile from a known policy and verify the SBPL is valid structure

**Verification**:
1. `make check` passes
2. Generate a profile from the test policy: `.venv/bin/avakill enforce sandbox --policy test-policy.yaml --dry-run`
3. Verify the output contains `(allow default)` and scoped `(deny ...)` rules
4. Verify the output does NOT contain bare `(deny file-write-data)` or `(deny process-exec)` without subpath scoping
```

---

## Session 6: Large — OpenAI Codex/ChatGPT CLI Hook Adapter (1 session)

```
AvaKill feature: Add OpenAI Codex CLI hook adapter.

**Problem**: The hook system supports claude-code, gemini-cli, cursor, and windsurf — but not OpenAI's CLI tools (Codex CLI). This is arguably the #1 agent ecosystem people want guardrails for. The beta tester had to fall back to macOS sandbox-exec which means no audit logs, no dashboard visibility, no `avakill logs` integration.

**Files to read first** (understand the existing pattern):
- Hook base class: `src/avakill/hooks/base.py` (class `HookAdapter` — abstract methods `parse_stdin()`, `format_response()`, main entry `run()`)
- Claude Code adapter: `src/avakill/hooks/claude_code.py` (reference implementation)
- Gemini CLI adapter: `src/avakill/hooks/gemini_cli.py` (another reference)
- Hook registry: `src/avakill/hooks/__init__.py` (decorator `register_adapter()`)
- Hook installer: `src/avakill/hooks/installer.py` (functions `install_hook()`, `detect_agents()`)
- Hook CLI: `src/avakill/cli/hook_cmd.py`
- Entry points: `pyproject.toml` `[project.scripts]` section
- Claude Code tests: `tests/test_hooks_claude_code.py` (test pattern reference)
- Also read: `docs/avakill-advanced.md` for hook specs and agent contracts

**Research needed first**: Before implementing, you need to understand how OpenAI's Codex CLI handles hooks/plugins. Check:
1. Read `docs/avakill-advanced.md` for any existing research on OpenAI's hook format
2. Search the codebase for any references to "openai", "codex", or "chatgpt" in comments or docs
3. The key questions are:
   - Does Codex CLI support pre-execution hooks (like Claude Code's hook system)?
   - What is the stdin/stdout contract? (JSON format of tool calls)
   - How are hooks installed? (config file location, format)

**What to build** (following the existing adapter pattern):

1. **New adapter**: `src/avakill/hooks/openai_codex.py`
   - Class `OpenAICodexAdapter(HookAdapter)`
   - Implement `parse_stdin()` → extract tool name and args from Codex's JSON format
   - Implement `format_response()` → format the allow/deny decision in Codex's expected output format
   - Entry point function `main()`

2. **Register the adapter**: Add `@register_adapter("openai-codex")` decorator

3. **Add entry point**: In `pyproject.toml` `[project.scripts]`:
   ```toml
   avakill-hook-openai-codex = "avakill.hooks.openai_codex:main"
   ```

4. **Hook installer support**: Update `src/avakill/hooks/installer.py`:
   - Add OpenAI Codex to `detect_agents()` — check for `codex` or `openai` CLI binary
   - Add installation logic in `install_hook()` — configure the hook in Codex's config location
   - Add to `SUPPORTED_AGENTS` list

5. **Update hook CLI**: Ensure `avakill hook install openai-codex` works
   - Update `src/avakill/cli/hook_cmd.py` if there's any hardcoded agent list

6. **Tests**: `tests/test_hooks_openai_codex.py`
   - Test `parse_stdin()` with sample Codex tool call JSON
   - Test `format_response()` with allow/deny decisions
   - Test the full `run()` flow with mocked stdin/daemon
   - Test hook detection and installation paths

**Important**: If Codex CLI doesn't support hooks yet or the format is undocumented, implement based on the best available information and add clear comments noting assumptions. The adapter should be functional when the hook system becomes available and easy to update when the exact spec is published. Check `docs/avakill-advanced.md` first — there may already be research on the expected format.

**Verification**:
1. `make check` passes
2. `avakill hook list` shows openai-codex as a supported agent
3. `echo '{"tool": "shell", "args": {"command": "rm -rf /"}}' | avakill-hook-openai-codex` works (with daemon or errors gracefully)
4. Tests pass for the new adapter
```

---

## Session 7: Large — Make `avakill launch` Work on macOS via sandbox-exec (1 session)

```
AvaKill feature: Make `avakill launch` work on macOS by using sandbox-exec under the hood.

**Problem**: `avakill launch` works on Linux (via Landlock) but silently does nothing on macOS. The `avakill enforce sandbox` command CAN generate macOS sandbox-exec profiles, but `avakill launch` doesn't use it. The beta tester's summary: "The single highest-impact improvement would be: make avakill launch work on macOS using sandbox-exec under the hood."

**Prerequisite**: Session 5 (fix .sb profile generator) should be done first, since this feature depends on generating correct sandbox-exec profiles.

**Files to read first**:
- Launch command: `src/avakill/cli/launch_cmd.py` (function `launch()`, lines 17-122)
- Core launcher: `src/avakill/launcher/core.py` (class `ProcessLauncher`)
- Launcher backends: `src/avakill/launcher/backends/` (look at all files — understand the backend pattern)
- Sandbox profile generator: `src/avakill/enforcement/sandbox_exec.py` (class `SandboxExecEnforcer`)
- Launch tests: `tests/test_cli_launch.py`
- Enforce tests: `tests/test_cli_enforce.py`

**What to build**:

1. **New launcher backend**: `src/avakill/launcher/backends/macos_sandbox.py`
   - Class `MacOSSandboxBackend` following the existing backend pattern
   - On `launch(command, policy)`:
     a. Generate a temporary `.sb` profile from the policy using `SandboxExecEnforcer.generate_profile()`
     b. Write it to a temp file
     c. Execute `sandbox-exec -f <profile> <command>` as a subprocess
     d. Stream stdout/stderr through to the user
     e. Clean up the temp profile on exit
     f. Return the subprocess exit code

2. **Register the backend**: Update the backend detection in `src/avakill/launcher/core.py`:
   - On `darwin` platform, use `MacOSSandboxBackend` instead of the noop backend
   - Check that `sandbox-exec` exists at `/usr/bin/sandbox-exec` (it's built into macOS)
   - Report `platform: macos, sandbox_applied: True, backend: sandbox-exec`

3. **Update the launch command**: In `src/avakill/cli/launch_cmd.py`:
   - Remove or update the "unsupported platform" message for darwin
   - Show the user what sandbox profile is being applied (with `--verbose` or always)
   - Add `--keep-profile` flag to save the generated .sb file for inspection
   - On `--dry-run`, print the generated .sb profile instead of running the command

4. **Error handling**:
   - If `sandbox-exec` is not found (shouldn't happen on macOS but handle it), error with instructions
   - If the profile generation fails, error with the specific issue
   - If `sandbox-exec` fails (exit code 126 or 127), translate to a human-readable error
   - If the wrapped process is killed by the sandbox (SIGKILL), explain that the sandbox blocked an operation

5. **Tests** (add to `tests/test_cli_launch.py`):
   - On macOS: `avakill launch --dry-run --policy test.yaml -- echo hello` prints the .sb profile
   - Backend detection selects `MacOSSandboxBackend` on darwin
   - `--keep-profile` writes the .sb file and prints its path
   - Mock `sandbox-exec` execution to test the full flow without actually sandboxing
   - Test error handling for sandbox violations

**Architecture notes**:
- The launcher backends should be a clean abstraction: `ProcessLauncher` calls `backend.launch(command, profile)` and doesn't know about platform specifics
- The `SandboxExecEnforcer` already does the YAML-to-SBPL translation — reuse it, don't duplicate
- Temp files should go in a predictable location (`~/.avakill/profiles/` or system temp) and be cleaned up

**Verification**:
1. `make check` passes
2. On macOS: `avakill launch --dry-run --policy avakill.yaml -- echo hello` prints a valid .sb profile (not "unsupported")
3. On macOS: `avakill launch --policy avakill.yaml -- echo hello` actually runs under sandbox-exec and outputs "hello"
4. On macOS: `avakill launch --policy avakill.yaml -- rm -rf /tmp/test` is blocked by the sandbox (if policy denies it)
5. `avakill launch --keep-profile --policy avakill.yaml -- echo hello` saves the .sb file and prints its path
```
