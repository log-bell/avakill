# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-02-16

### Added

- **Core policy engine** with YAML configuration, glob pattern matching, argument conditions (`args_match` / `args_not_match`), and sliding-window rate limiting.
- **Guard class** — main entry point with `evaluate()`, `evaluate_or_raise()`, `session()`, and `reload_policy()`.
- **`@protect` decorator** — wrap any Python function with policy checks. Supports sync and async functions, configurable deny behavior (`raise`, `return_none`, `callback`).
- **OpenAI interceptor** — `GuardedOpenAIClient` wraps an OpenAI client and automatically removes denied `tool_calls` from responses. Standalone `evaluate_tool_calls()` for manual evaluation.
- **Anthropic interceptor** — `GuardedAnthropicClient` wraps an Anthropic client and filters denied `tool_use` blocks from `response.content`.
- **LangChain interceptor** — `AgentGuardCallbackHandler` for `on_tool_start` interception. `create_agentguard_wrapper()` for LangGraph `ToolNode` integration.
- **MCP transparent proxy** — `MCPProxyServer` sits between MCP clients (Claude Desktop, Cursor) and upstream servers, intercepting `tools/call` requests via stdio transport. Supports newline-delimited JSON and Content-Length framing.
- **SQLite audit logger** — async batched writes (50 events or 100ms flush interval), WAL mode, full query/filter/stats API. Synchronous wrapper (`SyncSQLiteLogger`) for non-async contexts.
- **Event bus** — thread-safe in-process pub/sub singleton for real-time event streaming to the dashboard and other subscribers.
- **CLI** with five commands:
  - `agentguard init` — generate a policy file with framework auto-detection.
  - `agentguard validate` — validate policy syntax and print a rule summary.
  - `agentguard dashboard` — Rich terminal UI with live event stream, safety stats, and denied-tools bar chart.
  - `agentguard logs` — query audit logs with filters (`--tool`, `--denied-only`, `--since`, `--agent`, `--session`, `--json`). Includes `logs tail` for real-time following.
  - `agentguard mcp-proxy` — start the MCP transparent proxy from the command line.
- **Pydantic v2 models** — `ToolCall`, `Decision`, `AuditEvent`, `PolicyRule`, `PolicyConfig`, `RuleConditions`, `RateLimit` with full validation.
- **Environment variable substitution** — `${VAR_NAME}` syntax in YAML policy files.
- **Comprehensive test suite** — 322 tests covering the policy engine, Guard, all interceptors, decorator, MCP proxy, SQLite logger, and CLI.
- **Example scripts** — runnable demos for quickstart, OpenAI, Anthropic, LangChain/LangGraph, MCP proxy, and real-world disaster scenarios.
- **CI pipeline** — GitHub Actions with Python 3.10/3.11/3.12 matrix, Ruff, mypy, pytest with coverage, Codecov upload.

[Unreleased]: https://github.com/agentguard/agentguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentguard/agentguard/releases/tag/v0.1.0
