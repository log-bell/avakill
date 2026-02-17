# Contributing to AgentGuard

Thank you for your interest in contributing to AgentGuard! This project is early-stage and there's a lot to build. Whether it's a bug fix, new interceptor, or documentation improvement — we appreciate every contribution.

## Table of Contents

- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Adding a New Interceptor](#adding-a-new-interceptor)

## Development Setup

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/agentguard/agentguard.git
cd agentguard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in dev mode with all dependencies
make dev

# Verify everything works
make test
```

`make dev` installs the project in editable mode with all optional dependencies (`[dev,all]`) and configures pre-commit hooks.

### Available Make Commands

| Command | Description |
|---------|-------------|
| `make install` | Install the package |
| `make dev` | Install in dev mode + pre-commit hooks |
| `make test` | Run the test suite |
| `make lint` | Lint with Ruff |
| `make format` | Auto-format with Ruff |
| `make typecheck` | Type check with mypy |
| `make clean` | Remove build artifacts and caches |

## Architecture Overview

```
src/agentguard/
├── __init__.py              # Public API: Guard, protect, exceptions
├── core/
│   ├── engine.py            # Guard class (main entry point) + GuardSession
│   ├── policy.py            # PolicyEngine — YAML parsing + rule evaluation
│   ├── models.py            # Pydantic v2 models: ToolCall, Decision, PolicyConfig, etc.
│   └── exceptions.py        # PolicyViolation, ConfigError, RateLimitExceeded
├── interceptors/
│   ├── decorator.py         # @protect decorator for any Python function
│   ├── openai_wrapper.py    # GuardedOpenAIClient — wraps OpenAI client
│   ├── anthropic_wrapper.py # GuardedAnthropicClient — wraps Anthropic client
│   └── langchain_handler.py # AgentGuardCallbackHandler + LangGraph wrapper
├── mcp/
│   └── proxy.py             # MCPProxyServer — stdio transparent proxy
├── logging/
│   ├── base.py              # AuditLogger abstract base class
│   ├── sqlite_logger.py     # SQLiteLogger — async batched writes, WAL mode
│   └── event_bus.py         # EventBus — in-process pub/sub singleton
└── cli/
    ├── main.py              # Click CLI entry point
    ├── init_cmd.py          # agentguard init — generate policy files
    ├── validate_cmd.py      # agentguard validate — check policy syntax
    ├── logs_cmd.py          # agentguard logs — query audit trail
    ├── dashboard_cmd.py     # agentguard dashboard — Rich terminal UI
    └── mcp_proxy_cmd.py     # agentguard mcp-proxy — start the proxy
```

### How It Works

1. **Guard** is the main entry point. It wraps a `PolicyEngine` and an optional `AuditLogger`.
2. When `guard.evaluate(tool, args)` is called, the **PolicyEngine** iterates through rules top-to-bottom (first match wins).
3. Each rule checks: does the tool name match? Do the conditions match? Is the rate limit exceeded?
4. The result is a **Decision** (allowed/denied/require_approval) with the matching policy name and reason.
5. The decision is logged via the **AuditLogger** (async, non-blocking) and emitted to the **EventBus**.
6. **Interceptors** are thin wrappers that call `guard.evaluate()` at the right point in each framework's lifecycle.

### Key Design Decisions

- **First-match-wins** — like firewall rules (iptables, nginx). Specific rules go before general ones.
- **In-process evaluation** — no network calls, no sidecars. The policy engine is a pure function.
- **Thread-safe rate limiting** — sliding window with a deque + mutex. Works in multi-threaded agent loops.
- **Async audit logging** — fire-and-forget via `asyncio.create_task` or background thread. Never blocks the evaluation path.
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
# Lint (checks only, no changes)
make lint

# Auto-format (modifies files)
make format

# Type check
make typecheck

# All three at once
make lint && make typecheck
```

Pre-commit hooks run Ruff automatically on each commit. They are installed by `make dev`.

## Running Tests

```bash
# Run all tests
make test

# Run with coverage
pytest --cov=agentguard --cov-report=term-missing tests/

# Run a specific test file
pytest tests/test_policy_engine.py

# Run a specific test
pytest tests/test_guard.py::TestGuardEvaluate::test_allowed_call -v

# Run only async tests
pytest -k "async" tests/
```

The test suite uses:
- **pytest** with **pytest-asyncio** (`asyncio_mode = "auto"`)
- **SimpleNamespace** and **MagicMock** for framework mocks (no real API calls)
- **tmp_path** fixture for temporary policy files and databases

### Writing Tests

- Every new feature needs tests. Aim for the unhappy path too (errors, edge cases).
- Use `SimpleNamespace` to mock framework response objects (see `tests/test_openai_interceptor.py` for the pattern).
- Use the `sample_policy` fixture from `conftest.py` for basic policy needs, or create a `PolicyConfig` inline for specific test scenarios.
- Async tests work automatically — just write `async def test_*` and pytest-asyncio handles the event loop.

## Pull Request Process

1. **Fork** the repository and create a branch from `main`.
2. **Write code** — follow the code style guide above.
3. **Write tests** — cover new functionality and edge cases.
4. **Run the full suite** — `make test && make lint && make typecheck` must all pass.
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

We use two issue templates:

### Bug Reports

Include:
- AgentGuard version (`agentguard --version`)
- Python version
- Framework and version (OpenAI, Anthropic, etc.)
- Steps to reproduce
- Expected vs actual behavior
- Policy YAML (if relevant)

### Feature Requests

Include:
- What problem does this solve?
- What's your use case?
- Proposed solution (if you have one)
- Are you willing to implement it?

## Adding a New Interceptor

Want to add support for a new framework (CrewAI, AutoGen, etc.)? Here's the pattern:

1. **Create the interceptor** in `src/agentguard/interceptors/<framework>_wrapper.py`
2. **Follow the existing pattern** — look at `openai_wrapper.py` for the proxy approach or `langchain_handler.py` for the callback approach
3. **Core contract:** Extract `tool_name` and `args` from the framework's format, call `guard.evaluate(tool=name, args=args)`, handle the decision
4. **Add tests** in `tests/test_<framework>_interceptor.py` — use `SimpleNamespace` / `MagicMock`, no real API calls
5. **Add an example** in `examples/<framework>_example.py` — must run without an API key
6. **Add the optional dependency** in `pyproject.toml` under `[project.optional-dependencies]`
7. **Update the README** integration section

## Code of Conduct

Be respectful and constructive in all interactions. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
