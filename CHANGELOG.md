# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### Phase 1: Persistent Daemon
- **`DaemonServer`** — Unix domain socket server (`~/.avakill/avakill.sock`) with async connection handling, SIGHUP policy reload, and PID file management.
- **`DaemonClient`** — synchronous client for hook scripts with fail-closed behavior (denies on any error).
- **Wire protocol** — `EvaluateRequest`/`EvaluateResponse` models with newline-delimited JSON serialization.
- **`avakill daemon start/stop/status`** — CLI commands for daemon lifecycle management.
- **`avakill evaluate`** — evaluate tool calls via stdin JSON with exit codes (0=allow, 2=deny, 1=error).

#### Phase 2: Agent Hook Adapters
- **`ClaudeCodeAdapter`** — PreToolUse hook for Claude Code with `permissionDecision` response format.
- **`GeminiCliAdapter`** — BeforeTool hook for Gemini CLI.
- **`CursorAdapter`** — `beforeShellExecution`/`beforeMCPExecution`/`beforeReadFile` hooks for Cursor.
- **`WindsurfAdapter`** — Cascade Hooks (`pre_run_command`, `pre_write_code`, `pre_read_code`, `pre_mcp_tool_use`) with exit code 2 for deny.
- **`HookAdapter` base class** — abstract adapter with `parse_stdin()`/`format_response()` contract and standalone fallback mode.
- **Hook installer** — `avakill hook install/uninstall/list` CLI commands with auto-detection of installed agents.
- **Console scripts** — `avakill-hook-claude-code`, `avakill-hook-gemini-cli`, `avakill-hook-cursor`, `avakill-hook-windsurf`.

#### Phase 3: Tool Normalization, Policy Cascade & Enforcement Levels
- **`ToolNormalizer`** — translates agent-native tool names (e.g., Claude Code's `Bash` → `shell_execute`) to canonical names for universal policies.
- **`AGENT_TOOL_MAP`** — mapping table for Claude Code, Gemini CLI, Cursor, and Windsurf tool names.
- **`PolicyCascade`** — discovers and merges policies from system (`/etc/avakill/`), global (`~/.config/avakill/`), project (`.avakill/` or `avakill.yaml`), and local (`.avakill/policy.local.yaml`) levels.
- **Deny-wins merge semantics** — higher-level deny rules cannot be relaxed by lower levels.
- **Enforcement levels** — `hard`/`soft`/`advisory` per-rule enforcement via the `enforcement` field on `PolicyRule`.
- **`recovery_hint`** field on `AuditEvent` for actionable recovery suggestions.
- **Persistent rate limits** — `SQLiteBackend` for rate-limit timestamp persistence across restarts.

#### Phase 4: OS-Level Enforcement
- **`LandlockEnforcer`** — Linux 5.13+ filesystem access restrictions translated from deny policy rules. Irreversible once applied.
- **`SandboxExecEnforcer`** — macOS SBPL profile generation from policy rules.
- **`TetragonPolicyGenerator`** — Cilium `TracingPolicy` Kubernetes resource generation with kprobes and Sigkill actions.
- **`avakill enforce landlock/sandbox/tetragon`** — CLI commands with `--dry-run` and `--output` options.

#### Phase 5: Enterprise Compliance & Approvals
- **`ComplianceAssessor`** — automated compliance assessment against SOC 2 Type II, NIST AI RMF, EU AI Act, and ISO 42001 frameworks.
- **`ComplianceReporter`** — output compliance reports as Rich tables, JSON, or Markdown.
- **`avakill compliance report/gaps`** — CLI commands for generating assessments with `--framework` and `--format` options.
- **`ApprovalStore`** — SQLite-backed approval workflow with create, approve, deny, and expiry management.
- **`avakill approvals list/grant/reject`** — CLI commands for human-in-the-loop approval workflows.
- **`AuditAnalytics`** — denial trends, tool usage summaries, agent risk scores, and policy effectiveness analysis.

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
- **Comprehensive test suite** — 322 tests covering the policy engine, Guard, all interceptors, decorator, MCP proxy, SQLite logger, and CLI.
- **Example scripts** — runnable demos for quickstart, OpenAI, Anthropic, LangChain/LangGraph, MCP proxy, and real-world disaster scenarios.
- **CI pipeline** — GitHub Actions with Python 3.10/3.11/3.12 matrix, Ruff, mypy, pytest with coverage, Codecov upload.

[Unreleased]: https://github.com/avakill/avakill/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/avakill/avakill/releases/tag/v0.1.0
