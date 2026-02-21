# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-02-20

## [0.2.0] - 2026-02-20

### Added
- **Phase 1: Daemon + CLI** — `avakill daemon start/stop/status` over Unix domain socket or TCP localhost; `avakill evaluate` CLI for hook scripts; newline-delimited JSON protocol with `EvaluateRequest`/`EvaluateResponse`.
- **Phase 2: Agent hook adapters** — `avakill hook install/uninstall/list` for Claude Code, Gemini CLI, Cursor, and Windsurf; agent detection, idempotent install, hook binary resolution.
- **Phase 3: Tool normalization** — `ToolNormalizer` maps agent-specific tool names to canonical forms; multi-level policy cascade; enforcement levels (`hard`/`soft`/`advisory`).
- **Phase 4: OS-level enforcement** — `LandlockEnforcer` for Linux 5.13+ (unprivileged `restrict_self`); `SandboxExecEnforcer` for macOS (SBPL profile generation); `WindowsEnforcer` for Windows (Job Objects + privilege removal via `AdjustTokenPrivileges`); `avakill enforce` CLI with dry-run.
- **Shell metacharacter detection** — `is_shell_safe()` detects pipes, redirects, chaining, subshells, expansion, and dangerous builtins in shell commands.
- **`shell_safe` policy condition** — reject commands containing shell metacharacters before `args_match` evaluation; prevents allowlist bypasses via metacharacter injection.
- **`command_allowlist` policy condition** — first-token matching prevents prefix-smuggling attacks like `env VAR=val echo bypassed`. Unlike `args_match` (substring), matches only the actual command binary.
- **Self-protection for hook binaries** — blocks `rm`, redirect, truncate, `mv`, `chmod`, and write tools targeting `avakill-hook-*` binaries.
- **Self-protection for agent config files** — blocks writes to `.claude/settings.json`, `.gemini/settings.json`, `.cursor/hooks.json`, `.codeium/windsurf/hooks.json`, and related config files.
- **`--enforce` flag for daemon** — `avakill daemon start --enforce` applies OS-level restrictions (Landlock/sandbox-exec/Job Objects) before binding the socket.
- **Windows enforcement** — `WindowsEnforcer` creates Job Objects with child-process limits and irreversibly removes dangerous token privileges (`SeRestore`, `SeBackup`, `SeTakeOwnership`, `SeDebug`, `SeImpersonate`).
- **Hook installer improvements** — resolves absolute path to hook binary via `shutil.which()` + venv bin dir; smoke test verifies binary exists and executes.
- **CI/CD overhaul** — parallel CI jobs with `uv`, Python 3.10–3.13 matrix, concurrency groups, `alls-green` gate job; release workflow with separate build/publish jobs, version-tag validation, smoke test, auto GitHub Release creation.
- **Single-source versioning** — `__version__` reads from `importlib.metadata`; `pyproject.toml` is the sole version source.
- **Version bump script** — `scripts/bump-version.py` updates `pyproject.toml` and `CHANGELOG.md` in one command.

### Fixed
- Fix all ruff lint errors (31) — import sorting, unused imports, line length, `raise from`, broad `pytest.raises`.
- Fix all mypy type errors (13) — missing stubs, `no-any-return`, `no-redef`, `union-attr`, literal types.
- Remove unused testimonial CSS/JS from landing page.
- Auto-select default template in non-TTY for `avakill init` (no interactive prompt in CI/pipes).
- Fix `avakill logs` table rendering (column alignment, empty-state message).
- Fix documentation mismatches in `avakill init` output and README examples.
- Resolve UX paper cuts: install guidance, nav labels, coming-soon badges.
- Fix stale version assertions in tests (version drift between `pyproject.toml` and test files).

### Changed
- Restructure README roadmap into maturity tiers (Foundation / Growth / Enterprise).
- Add integration row labels to landing page feature matrix.
- Makefile targets use `uv` instead of `pip`/`twine` (with auto-detection fallback).

## [0.1.0] - 2026-02-16

### Added

- **Core policy engine** with YAML configuration, glob pattern matching, argument conditions (`args_match` / `args_not_match`), and sliding-window rate limiting.
- **Guard class** — main entry point with `evaluate()`, `evaluate_or_raise()`, `session()`, and `reload_policy()`.
- **`@protect` decorator** — wrap any Python function with policy checks. Supports sync and async functions, configurable deny behavior (`raise`, `return_none`, `callback`).
- **OpenAI interceptor** — `GuardedOpenAIClient` wraps an OpenAI client and automatically removes denied `tool_calls` from responses. Standalone `evaluate_tool_calls()` for manual evaluation.
- **Anthropic interceptor** — `GuardedAnthropicClient` wraps an Anthropic client and filters denied `tool_use` blocks from `response.content`.
- **LangChain interceptor** — `AvaKillCallbackHandler` for `on_tool_start` interception. `create_avakill_wrapper()` for LangGraph `ToolNode` integration.
- **MCP transparent proxy** — `MCPProxyServer` sits between MCP clients (Claude Desktop, Cursor) and upstream servers, intercepting `tools/call` requests via stdio transport. Supports newline-delimited JSON and Content-Length framing.
- **SQLite audit logger** — async batched writes (50 events or 100ms flush interval), WAL mode, full query/filter/stats API. Synchronous wrapper (`SyncSQLiteLogger`) for non-async contexts.
- **Event bus** — thread-safe in-process pub/sub singleton for real-time event streaming to the dashboard and other subscribers.
- **CLI** with five commands:
  - `avakill init` — generate a policy file with framework auto-detection.
  - `avakill validate` — validate policy syntax and print a rule summary.
  - `avakill dashboard` — Rich terminal UI with live event stream, safety stats, and denied-tools bar chart.
  - `avakill logs` — query audit logs with filters (`--tool`, `--denied-only`, `--since`, `--agent`, `--session`, `--json`). Includes `logs tail` for real-time following.
  - `avakill mcp-proxy` — start the MCP transparent proxy from the command line.
- **Pydantic v2 models** — `ToolCall`, `Decision`, `AuditEvent`, `PolicyRule`, `PolicyConfig`, `RuleConditions`, `RateLimit` with full validation.
- **Environment variable substitution** — `${VAR_NAME}` syntax in YAML policy files.
- **Comprehensive test suite** covering the policy engine, Guard, all interceptors, decorator, MCP proxy, SQLite logger, and CLI.
- **Example scripts** — runnable demos for quickstart, OpenAI, Anthropic, LangChain/LangGraph, MCP proxy, and real-world disaster scenarios.
- **CI pipeline** — GitHub Actions with Python 3.10/3.11/3.12 matrix, Ruff, mypy, pytest with coverage, Codecov upload.

[Unreleased]: https://github.com/log-bell/avakill/compare/v0.3.0...HEAD
[0.2.0]: https://github.com/log-bell/avakill/compare/v0.1.0...v0.2.0
[0.3.0]: https://github.com/log-bell/avakill/compare/v0.2.0...v0.3.0
[0.1.0]: https://github.com/log-bell/avakill/releases/tag/v0.1.0
