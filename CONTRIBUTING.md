# Contributing to AvaKill

Thank you for your interest in contributing to AvaKill! This project is early-stage and there's a lot to build. Whether it's a bug fix, new hook adapter, or documentation improvement — we appreciate every contribution.

## Table of Contents

- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Adding a New Hook Adapter](#adding-a-new-hook-adapter)
- [Adding a New Interceptor](#adding-a-new-interceptor)

## Development Setup

**Requirements:** Python 3.10+, [uv](https://docs.astral.sh/uv/) (recommended) or pip

```bash
# Clone the repository
git clone https://github.com/log-bell/avakill.git
cd avakill

# Install in dev mode with all dependencies + pre-commit hooks
make dev

# Verify everything works
make check   # runs lint + typecheck + tests
```

### Available Make Commands

| Command | Description |
|---------|-------------|
| `make dev` | Install in dev mode with all extras + pre-commit hooks |
| `make check` | Run lint + typecheck + tests (use this before submitting PRs) |
| `make test` | Run the test suite |
| `make test-cov` | Run tests with coverage report |
| `make lint` | Lint with Ruff |
| `make format` | Auto-format with Ruff |
| `make typecheck` | Type check with mypy |
| `make clean` | Remove build artifacts and caches |
| `make build` | Full check + clean + build wheel |

## Architecture Overview

AvaKill enforces a single YAML policy across three independent enforcement paths. Each path works standalone — no daemon required.

```
avakill.yaml (one policy file)
    |
    ├── Hooks (Claude Code, Cursor, Windsurf, Gemini CLI, Codex)
    |     → work standalone, evaluate in-process
    |
    ├── MCP Proxy (wraps MCP servers)
    |     → works standalone, evaluate in-process
    |
    ├── OS Sandbox (launch + profiles)
    |     → works standalone, OS-level enforcement
    |
    └── Daemon (optional)
          → shared evaluation, audit logging
          → hooks/proxy CAN talk to it if running
          → enables: logs, fix, tracking, approvals, metrics
```

### Source Layout

```
src/avakill/
├── __init__.py                 # Public API: Guard, protect, exceptions, lazy imports
├── core/
│   ├── engine.py               # Guard class (main entry point) + GuardSession
│   ├── policy.py               # PolicyEngine — YAML parsing + rule evaluation
│   ├── models.py               # Pydantic v2 models: ToolCall, Decision, PolicyConfig, etc.
│   ├── exceptions.py           # PolicyViolation, ConfigError, RateLimitExceeded
│   ├── normalization.py        # ToolNormalizer — agent-native → canonical name mapping
│   ├── cascade.py              # PolicyCascade — multi-level policy discovery and merge
│   ├── shell_analysis.py       # Shell safety checks (metacharacter detection)
│   ├── command_parser.py       # Command allowlist (first-token extraction)
│   ├── content_scanner.py      # Secret/PII/prompt-injection scanning
│   ├── path_resolution.py      # Path resolution (~, $HOME, symlinks, ..)
│   ├── self_protection.py      # Hardcoded anti-tampering rules
│   ├── integrity.py            # PolicyIntegrity — HMAC-SHA256 + Ed25519 signing
│   ├── approval.py             # ApprovalStore — SQLite-backed approval workflow
│   ├── rate_limit_store.py     # RateLimitBackend protocol + SQLiteBackend
│   ├── session_store.py        # Session management for grouped calls
│   ├── call_tagger.py          # Semantic tagging of tool calls
│   ├── correlation.py          # Cross-call correlation tracking
│   ├── recovery.py             # Recovery hint generation for avakill fix
│   ├── watcher.py              # PolicyWatcher — file change detection and auto-reload
│   └── audit_hooks.py          # C-level audit hooks for tamper resistance
├── hooks/
│   ├── __init__.py             # Adapter registry (ADAPTERS dict, get_adapter())
│   ├── base.py                 # HookAdapter abstract base class
│   ├── installer.py            # install_hook(), uninstall_hook(), detect_agents()
│   ├── agent_context.py        # Agent detection and context resolution
│   ├── claude_code.py          # ClaudeCodeAdapter — PreToolUse hook
│   ├── gemini_cli.py           # GeminiCliAdapter — BeforeTool hook
│   ├── cursor.py               # CursorAdapter — beforeShellExecution hook
│   ├── windsurf.py             # WindsurfAdapter — Cascade Hooks
│   └── openai_codex.py         # OpenAICodexAdapter — Codex hook
├── mcp/
│   ├── config.py               # MCP config discovery and parsing
│   ├── proxy.py                # MCPProxyServer — stdio transparent proxy
│   └── wrapper.py              # MCP server wrapping/unwrapping logic
├── launcher/
│   ├── core.py                 # ProcessLauncher — OS sandbox orchestrator
│   ├── pty_relay.py            # PTY relay for sandboxed processes
│   └── backends/
│       ├── darwin_backend.py   # macOS sandbox-exec backend
│       ├── darwin_sbpl.py      # SBPL profile generation
│       ├── landlock_backend.py # Linux Landlock backend
│       ├── windows_backend.py  # Windows AppContainer backend
│       └── ...
├── interceptors/
│   ├── decorator.py            # @protect decorator for any Python function
│   ├── openai_wrapper.py       # GuardedOpenAIClient — wraps OpenAI client
│   ├── anthropic_wrapper.py    # GuardedAnthropicClient — wraps Anthropic client
│   └── langchain_handler.py    # AvaKillCallbackHandler + LangGraph wrapper
├── daemon/
│   ├── server.py               # DaemonServer — Unix socket server with SIGHUP reload
│   ├── client.py               # DaemonClient — synchronous client for hook scripts
│   ├── protocol.py             # EvaluateRequest/EvaluateResponse wire protocol
│   └── transport.py            # Transport abstraction (Unix socket, TCP)
├── enforcement/
│   ├── landlock.py             # LandlockEnforcer — Linux filesystem restrictions
│   ├── sandbox_exec.py         # SandboxExecEnforcer — macOS SBPL profiles
│   ├── tetragon.py             # TetragonPolicyGenerator — Kubernetes eBPF
│   └── windows.py              # WindowsEnforcer — AppContainer
├── compliance/
│   ├── assessor.py             # ComplianceAssessor — framework compliance checks
│   ├── frameworks.py           # SOC 2, NIST AI RMF, EU AI Act, ISO 42001
│   └── reporter.py             # ComplianceReporter — table/JSON/Markdown output
├── logging/
│   ├── base.py                 # AuditLogger abstract base class
│   ├── sqlite_logger.py        # SQLiteLogger — async batched writes, WAL mode
│   └── event_bus.py            # EventBus — in-process pub/sub singleton
├── analytics/
│   └── engine.py               # AuditAnalytics — denial trends, risk scores
├── profiles/
│   ├── loader.py               # Agent profile loader (openclaw, aider, swe-agent, etc.)
│   └── models.py               # Profile models
├── cli/
│   ├── main.py                 # Click CLI entry point + command registration
│   ├── setup_cmd.py            # avakill setup (interactive wizard)
│   ├── rules_cmd.py            # avakill rules / rules list / rules create
│   ├── validate_cmd.py         # avakill validate
│   ├── evaluate_cmd.py         # avakill evaluate
│   ├── fix_cmd.py              # avakill fix
│   ├── hook_cmd.py             # avakill hook install/uninstall/list
│   ├── mcp_wrap_cmd.py         # avakill mcp-wrap / mcp-unwrap
│   ├── launch_cmd.py           # avakill launch
│   ├── logs_cmd.py             # avakill logs / logs tail
│   ├── tracking_cmd.py         # avakill tracking on/off/status
│   ├── daemon_cmd.py           # avakill daemon start/stop/status
│   ├── reset_cmd.py            # avakill reset
│   ├── approval_cmd.py         # avakill approvals list/grant/reject
│   ├── approve_cmd.py          # avakill approve
│   ├── review_cmd.py           # avakill review
│   ├── compliance_cmd.py       # avakill compliance report/gaps
│   ├── sign_cmd.py             # avakill sign
│   ├── verify_cmd.py           # avakill verify
│   ├── keygen_cmd.py           # avakill keygen
│   ├── harden_cmd.py           # avakill harden
│   ├── check_hardening_cmd.py  # avakill check-hardening
│   ├── schema_cmd.py           # avakill schema
│   ├── profile_cmd.py          # avakill profile list/show
│   ├── enforce_cmd.py          # avakill enforce landlock/sandbox/tetragon
│   ├── metrics_cmd.py          # avakill metrics
│   ├── rule_catalog.py         # Rule catalog (81 rules, 14 categories)
│   ├── scanner.py              # Project scanner (sensitive file detection)
│   ├── recovery_panel.py       # Rich recovery panel for avakill fix
│   ├── config.py               # CLI config helpers
│   └── banner.py               # CLI banner/branding
└── ...
```

### How Evaluation Works

1. **Guard** is the main entry point. It wraps a `PolicyEngine` and an optional `AuditLogger`.
2. When `guard.evaluate(tool, args)` is called, self-protection checks run first (hardcoded, not configurable).
3. The **PolicyEngine** iterates rules top-to-bottom (first match wins), checking: tool name match → conditions (`args_match`, `shell_safe`, `command_allowlist`, `path_match`, `content_scan`) → rate limit.
4. The result is a **Decision** (allowed/denied/require_approval) with the matching policy name and reason.
5. The decision is logged via the **AuditLogger** (async, non-blocking) and emitted to the **EventBus**.

### Three Enforcement Paths

- **Hooks** — hook binaries (`avakill-hook-claude-code`, etc.) intercept tool calls inside AI agents. Each hook translates the agent's native format, evaluates against policy, and returns allow/deny. Works standalone or delegates to the daemon.
- **MCP Proxy** — `avakill mcp-wrap` rewrites agent MCP configs to route tool calls through `avakill-shim` (a Go binary) or `avakill mcp-proxy` (Python). Intercepts `tools/call` JSON-RPC messages.
- **OS Sandbox** — `avakill launch` runs agents inside OS-level sandboxes (Landlock, sandbox-exec, AppContainer, Tetragon). Restricts filesystem, network, and process creation at the kernel level.

### Key Design Decisions

- **First-match-wins** — like firewall rules (iptables, nginx). Specific rules go before general ones.
- **In-process evaluation** — no network calls, no sidecars. The policy engine is a pure function (<1ms).
- **Thread-safe rate limiting** — sliding window with a deque + mutex.
- **Async audit logging** — fire-and-forget. Never blocks the evaluation path.
- **Framework interceptors are proxies** — they wrap the real client, delegating all non-tool-call methods via `__getattr__`.

## Code Style

This project uses **[Ruff](https://docs.astral.sh/ruff/)** for linting and formatting, and **[mypy](https://mypy.readthedocs.io/)** for type checking.

### Rules

- **Line length:** 100 characters
- **Target:** Python 3.10
- **Ruff rules:** `E`, `W`, `F`, `I`, `UP`, `B`, `SIM`
- **Type annotations:** Required for all public functions. Use `from __future__ import annotations` for modern syntax.
- **Docstrings:** Google style. Required for all public classes and methods.
- **Imports:** Sorted by Ruff (`I` rule). Standard library, third-party, local — each group separated by a blank line.

### Running Checks

```bash
# Run all checks (lint + typecheck + tests) — use this before submitting PRs
make check

# Individual checks
make lint        # Ruff lint (checks only)
make format      # Ruff format (modifies files)
make typecheck   # mypy
make test        # pytest
```

Pre-commit hooks run Ruff automatically on each commit. They are installed by `make dev`.

## Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run a specific test file
uv run pytest tests/test_policy_engine.py

# Run a specific test class or method
uv run pytest tests/test_guard.py::TestGuardEvaluate::test_allowed_call -v

# Run only tests matching a keyword
uv run pytest -k "shell_safe" tests/
```

The test suite (~2,100 tests) uses:
- **pytest** with **pytest-asyncio** (`asyncio_mode = "auto"`)
- **Class-based grouping** — related tests grouped in `class Test*`
- **SimpleNamespace** and **MagicMock** for framework mocks (no real API calls)
- **tmp_path** fixture for temporary policy files and databases

### Writing Tests

- Every new feature needs tests. Cover the unhappy path too (errors, edge cases).
- Use `SimpleNamespace` to mock framework response objects (see `tests/test_openai_interceptor.py` for the pattern).
- Create a `PolicyConfig` inline for specific test scenarios, or use `Guard(policy=policy, self_protection=False)` for isolated tests.
- Async tests work automatically — just write `async def test_*` and pytest-asyncio handles the event loop.
- Tests that use `EventBus` need the autouse `_reset_event_bus()` fixture — see existing test files for the pattern.
- Test naming convention: `test_<feature>_<expected_outcome>`

## Pull Request Process

1. **Fork** the repository and create a branch from `main`.
2. **Write code** — follow the code style guide above.
3. **Write tests** — cover new functionality and edge cases.
4. **Run `make check`** — lint, typecheck, and tests must all pass.
5. **Update docs** if your changes affect the public API or add new features.
6. **Submit your PR** with a clear description of what changed and why.

### PR Title Format

Use a conventional commit-style prefix:

- `feat: add CrewAI interceptor`
- `fix: handle empty tool_calls in OpenAI wrapper`
- `docs: update MCP proxy configuration example`
- `refactor: extract rate limiter into separate class`
- `test: add edge case tests for glob matching`

### What We Look For

- Does it solve a real problem?
- Are there tests?
- Does it follow existing patterns?
- Is the code clear without excessive comments?
- Does it avoid unnecessary dependencies?

## Issue Guidelines

### Bug Reports

Include:
- AvaKill version (`avakill --version`)
- Python version
- OS (macOS, Linux, Windows)
- Agent being used (Claude Code, Cursor, etc.)
- Steps to reproduce
- Expected vs actual behavior
- Policy YAML (if relevant)

### Feature Requests

Include:
- What problem does this solve?
- What's your use case?
- Proposed solution (if you have one)
- Are you willing to implement it?

## Adding a New Hook Adapter

Want to add support for a new AI coding agent (e.g., Aider, Continue, Zed)? Here's the process:

1. **Create the adapter** in `src/avakill/hooks/<agent_name>.py`

2. **Subclass `HookAdapter`** and implement the two required methods:
   ```python
   from avakill.hooks.base import HookAdapter
   from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse

   class MyAgentAdapter(HookAdapter):
       agent_name = "my-agent"

       def parse_stdin(self, raw: str) -> EvaluateRequest:
           """Parse the agent's hook payload into an EvaluateRequest."""
           data = json.loads(raw)
           return EvaluateRequest(
               agent=self.agent_name,
               tool=data["tool_name"],
               args=data.get("arguments", {}),
           )

       def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
           """Format the response for the agent. Returns (stdout, exit_code)."""
           if response.decision == "deny":
               return json.dumps({"blocked": True, "reason": response.reason}), 0
           return None, 0  # Allow: no output
   ```

3. **Add tool name normalization** in `src/avakill/core/normalization.py`:
   ```python
   AGENT_TOOL_MAP["my-agent"] = {
       "agent_native_name": "canonical_name",
       # ...
   }
   ```

4. **Add agent detection** in `src/avakill/hooks/installer.py` — implement logic to detect if the agent is installed and to write/remove the hook configuration file.

5. **Add a console script** in `pyproject.toml`:
   ```toml
   [project.scripts]
   avakill-hook-my-agent = "avakill.hooks.my_agent:main"
   ```

6. **Write tests** in `tests/test_hooks_my_agent.py`:
   - Test `parse_stdin()` with valid and malformed payloads
   - Test `format_response()` for allow and deny decisions
   - Test the full `run()` flow with mocked stdin/daemon

7. **Register the adapter** — add a lazy import in `src/avakill/hooks/__init__.py` so `get_adapter("my-agent")` returns your class, and add `"my-agent"` to the `--agent` choices in `src/avakill/cli/hook_cmd.py`.

Look at `src/avakill/hooks/claude_code.py` and `src/avakill/hooks/openai_codex.py` for reference implementations.

## Adding a New Interceptor

Want to add support for a new framework (CrewAI, AutoGen, etc.)? Here's the pattern:

1. **Create the interceptor** in `src/avakill/interceptors/<framework>_wrapper.py`
2. **Follow the existing pattern** — look at `openai_wrapper.py` for the proxy approach or `langchain_handler.py` for the callback approach.
3. **Core contract:** Extract `tool_name` and `args` from the framework's format, call `guard.evaluate(tool=name, args=args)`, handle the decision.
4. **Add tests** in `tests/test_<framework>_interceptor.py` — use `SimpleNamespace` / `MagicMock`, no real API calls.
5. **Add the optional dependency** in `pyproject.toml` under `[project.optional-dependencies]`.
6. **Add a lazy import** in `src/avakill/__init__.py` so `from avakill import GuardedMyClient` works.

## Code of Conduct

Be respectful and constructive in all interactions. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
