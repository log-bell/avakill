# API Reference

This is the public Python API for AvaKill. All classes listed here are importable from the top-level `avakill` package unless otherwise noted.

```python
from avakill import Guard, protect, PolicyViolation, ConfigError, RateLimitExceeded
```

## avakill.Guard

The central AvaKill controller. Wraps a `PolicyEngine`, evaluates tool calls, records audit events, and manages self-protection.

### Constructor

```python
Guard(
    policy: str | Path | dict | PolicyConfig | None = None,
    logger: AuditLogger | None = None,
    agent_id: str | None = None,
    self_protection: bool = True,
    signing_key: bytes | None = None,
    verify_key: bytes | None = None,
    rate_limit_backend: RateLimitBackend | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy` | `str \| Path \| dict \| PolicyConfig \| None` | `None` | Path to YAML file, raw dict, PolicyConfig object, or `None` to auto-detect `avakill.yaml` in cwd |
| `logger` | `AuditLogger \| None` | `None` | Audit logger for recording events. If `None`, no logging. |
| `agent_id` | `str \| None` | `None` | Default agent identifier for attribution |
| `self_protection` | `bool` | `True` | Enable hardcoded self-protection rules. Only set `False` for testing. |
| `signing_key` | `bytes \| None` | `None` | HMAC signing key. If `None`, reads `AVAKILL_POLICY_KEY` env var. |
| `verify_key` | `bytes \| None` | `None` | Ed25519 public key. If `None`, reads `AVAKILL_VERIFY_KEY` env var. |
| `rate_limit_backend` | `RateLimitBackend \| None` | `None` | Persistent backend for rate-limit timestamps. `None` = in-memory only. |

**Raises:** `ConfigError` if the policy cannot be loaded or parsed.

### evaluate()

```python
Guard.evaluate(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Decision
```

Evaluate a tool call against the loaded policy. Self-protection rules run first, then user-defined policy rules.

| Parameter | Description |
|-----------|-------------|
| `tool` | Name of the tool being invoked |
| `args` | Arguments passed to the tool |
| `agent_id` | Override agent identifier (falls back to Guard default) |
| `session_id` | Optional session identifier |
| `metadata` | Arbitrary metadata attached to the call |

**Returns:** A `Decision` object.

```python
decision = guard.evaluate(tool="execute_sql", args={"query": "DROP TABLE users"})
if not decision.allowed:
    print(f"Blocked by {decision.policy_name}: {decision.reason}")
```

### evaluate_or_raise()

```python
Guard.evaluate_or_raise(
    tool: str,
    args: dict[str, Any] | None = None,
    **kwargs,
) -> Decision
```

Same as `evaluate()` but raises `PolicyViolation` when the decision is denied.

**Returns:** The `Decision` (always `allowed=True`).

**Raises:** `PolicyViolation` on denial, `RateLimitExceeded` on rate limit.

### session()

```python
Guard.session(
    agent_id: str | None = None,
    session_id: str | None = None,
) -> GuardSession
```

Create a session context manager with fixed agent and session IDs.

```python
with guard.session(agent_id="my-agent") as session:
    session.evaluate(tool="search", args={"q": "hello"})
    session.evaluate(tool="read_file", args={"path": "/tmp/data.txt"})
    print(session.call_count)  # → 2
```

### reload_policy()

```python
Guard.reload_policy(path: str | Path | None = None) -> None
```

Hot-reload the policy file without restarting. If `path` is `None`, reloads from the original path.

**Raises:** `ConfigError` if the policy cannot be loaded.

### watch()

```python
Guard.watch(**kwargs) -> PolicyWatcher
```

Create a `PolicyWatcher` that auto-reloads when the policy file changes on disk.

```python
watcher = guard.watch()
await watcher.start()
# Policy reloads automatically on file change
await watcher.stop()
```

**Raises:** `RuntimeError` if a watcher is already active. `ValueError` if no file-based policy.

### unwatch()

```python
await Guard.unwatch() -> None
```

Stop and remove the active `PolicyWatcher`.

### policy_status

```python
Guard.policy_status -> str
```

Current integrity status:

| Value | Meaning |
|-------|---------|
| `"hardened"` | Signature verified + C-level audit hooks active |
| `"verified"` | Signature verified |
| `"last-known-good"` | Current signature invalid, using cached policy |
| `"deny-all"` | No valid policy available, all calls blocked |
| `"unsigned"` | No signing key configured |

---

## avakill.GuardSession

Wraps a Guard with fixed `agent_id` and `session_id`. Created via `guard.session()`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `agent_id` | `str \| None` | Agent identifier for this session |
| `session_id` | `str` | Session identifier (auto-generated UUID if not provided) |
| `call_count` | `int` | Number of calls made in this session |

### Methods

- `evaluate(tool, args, **kwargs) -> Decision` — same as `Guard.evaluate()` with session context
- `evaluate_or_raise(tool, args, **kwargs) -> Decision` — same as `Guard.evaluate_or_raise()` with session context

Supports context manager protocol (`with guard.session() as s:`).

---

## avakill.protect

Decorator that wraps a function with AvaKill policy checks. Supports sync and async functions.

```python
@protect
def my_tool(arg: str): ...

@protect(guard=guard, tool_name="custom_name", on_deny="return_none")
def my_tool(arg: str): ...

@protect(policy="strict.yaml", on_deny="callback", deny_callback=my_handler)
async def risky_tool(arg: str): ...
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `guard` | `Guard \| None` | `None` | Guard instance. If `None` and `policy` given, creates one. If both `None`, auto-detects. |
| `policy` | `str \| Path \| None` | `None` | Path to YAML policy file (creates Guard internally) |
| `tool_name` | `str \| None` | `None` | Override tool name (defaults to `fn.__name__`) |
| `on_deny` | `"raise" \| "return_none" \| "callback"` | `"raise"` | Behavior when denied |
| `deny_callback` | `Callable \| None` | `None` | Called when `on_deny="callback"`. Receives `(tool_name, decision, args, kwargs)`. |

---

## Exceptions

### avakill.PolicyViolation

Raised when a tool call is denied by policy.

```python
try:
    guard.evaluate_or_raise(tool="delete_user", args={"id": "123"})
except PolicyViolation as e:
    print(e.tool_name)     # "delete_user"
    print(e.decision)      # Decision object
```

### avakill.ConfigError

Raised when a policy file cannot be loaded or parsed.

### avakill.RateLimitExceeded

Raised when a rate limit is exceeded. Subclass of `PolicyViolation`.

```python
try:
    guard.evaluate_or_raise(tool="web_search", args={"q": "test"})
except RateLimitExceeded as e:
    print(e.decision.reason)  # Rate limit details
```

---

## Data Models

### Decision

The result of evaluating a tool call. Immutable (Pydantic frozen model).

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the tool call is permitted |
| `action` | `"allow" \| "deny" \| "require_approval"` | The action taken |
| `policy_name` | `str \| None` | Name of the matching policy rule |
| `reason` | `str \| None` | Human-readable explanation |
| `timestamp` | `datetime` | When the decision was made |
| `latency_ms` | `float` | Evaluation time in milliseconds |

### ToolCall

Represents an intercepted tool call. Available from `avakill.core.models`.

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | `str` | Name of the tool |
| `arguments` | `dict[str, Any]` | Arguments passed to the tool |
| `agent_id` | `str \| None` | Agent identifier |
| `session_id` | `str \| None` | Session identifier |
| `timestamp` | `datetime` | When intercepted (UTC) |
| `metadata` | `dict[str, Any]` | Arbitrary metadata |

### AuditEvent

Links a tool call to its decision. Available from `avakill.core.models`.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | UUID4 identifier |
| `tool_call` | `ToolCall` | The intercepted call |
| `decision` | `Decision` | The policy decision |
| `execution_result` | `Any \| None` | Tool result if allowed |
| `error` | `str \| None` | Error if execution failed |

---

## Framework Integrations

### avakill.GuardedOpenAIClient

Wraps an OpenAI client to automatically filter denied tool calls from responses.

```python
from openai import OpenAI
from avakill import GuardedOpenAIClient

client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")
response = client.chat.completions.create(model="gpt-4o", tools=[...], messages=[...])
# Denied tool_calls are removed from the response
# response.avakill_decisions contains all decisions
```

### avakill.GuardedAnthropicClient

Wraps an Anthropic client to filter denied `tool_use` blocks from responses.

```python
from anthropic import Anthropic
from avakill import GuardedAnthropicClient

client = GuardedAnthropicClient(Anthropic(), policy="avakill.yaml")
response = client.messages.create(model="claude-sonnet-4-5-20250514", tools=[...], messages=[...])
# Denied tool_use blocks are removed from response.content
```

### avakill.AvaKillCallbackHandler

LangChain/LangGraph callback handler that intercepts tool calls.

```python
from avakill import AvaKillCallbackHandler

handler = AvaKillCallbackHandler(policy="avakill.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
# Raises PolicyViolation before the tool executes
```

### avakill.MCPProxyServer

MCP transparent proxy that intercepts `tools/call` requests.

```python
from avakill import MCPProxyServer

proxy = MCPProxyServer(
    upstream_cmd="python",
    upstream_args=["server.py"],
    policy="avakill.yaml",
    log_db="audit.db",
)
await proxy.run()
```

See the [MCP Proxy Guide](mcp-proxy.md) for detailed usage.

---

## Security & Integrity

### avakill.PolicyIntegrity

Manages policy file signing, verification, and fail-closed loading.

```python
from avakill import PolicyIntegrity

# Sign a file with HMAC
sig_path = PolicyIntegrity.sign_file("avakill.yaml", key_bytes)

# Sign with Ed25519
sig_path = PolicyIntegrity.sign_file_ed25519("avakill.yaml", private_key_bytes)

# Verify (auto-detects HMAC or Ed25519)
valid = PolicyIntegrity.verify_file("avakill.yaml", key_bytes)
```

### avakill.FileSnapshot

Immutable snapshot of a file's state for integrity verification.

```python
from avakill import FileSnapshot

snap = FileSnapshot.from_path("avakill.yaml")
print(snap.sha256)  # SHA-256 hash
print(snap.size)    # File size in bytes
print(snap.mode)    # File permissions

ok, message = snap.verify("avakill.yaml")
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | `str` | Resolved absolute path |
| `sha256` | `str` | SHA-256 content hash |
| `size` | `int` | File size in bytes |
| `mtime_ns` | `int` | Modification time (nanoseconds) |
| `inode` | `int` | Inode number |
| `device` | `int` | Device ID |
| `mode` | `int` | File permissions |
| `uid` | `int` | Owner UID |
| `gid` | `int` | Owner GID |

---

## Schema & Prompts

### avakill.get_json_schema

```python
from avakill import get_json_schema
schema = get_json_schema()  # Returns dict — JSON Schema for PolicyConfig
```

### avakill.generate_prompt

```python
from avakill import generate_prompt
prompt = generate_prompt(
    tools_list=["file_read", "shell_exec", "db_query"],
    use_case="code assistant",
)
# Returns a self-contained LLM prompt for generating policies
```

---

## Observability

### avakill.get_metrics_registry

```python
from avakill import get_metrics_registry
from prometheus_client import start_http_server

registry = get_metrics_registry()
start_http_server(9090, registry=registry)
```

Returns the Prometheus `CollectorRegistry` with all AvaKill metrics. Uses its own registry (not the global default) to avoid name collisions.

### avakill.PolicyWatcher

Watches a policy file for changes and auto-reloads the Guard.

```python
from avakill import PolicyWatcher

watcher = guard.watch()
await watcher.start()
# ... policy file changes are detected and reloaded ...
await watcher.stop()
```

Or as an async context manager:

```python
async with guard.watch() as watcher:
    # Policy auto-reloads on file changes
    pass
```

---

## Internal (for contributors)

These are not part of the public API and may change between versions.

| Class | Module | Description |
|-------|--------|-------------|
| `PolicyEngine` | `avakill.core.policy` | Parses YAML and evaluates tool calls with first-match-wins |
| `PolicyConfig` | `avakill.core.models` | Pydantic model for the top-level YAML structure |
| `PolicyRule` | `avakill.core.models` | Pydantic model for a single rule |
| `SQLiteLogger` | `avakill.logging.sqlite_logger` | Async SQLite audit logger with batched writes |
| `SyncSQLiteLogger` | `avakill.logging.sqlite_logger` | Synchronous wrapper for non-async contexts |
| `EventBus` | `avakill.logging.event_bus` | In-process event pub/sub (singleton) |
| `SelfProtection` | `avakill.core.self_protection` | Hardcoded self-protection rules |
| `AuditHookManager` | `avakill.core.audit_hooks` | Python `sys.addaudithook()` manager |
| `RateLimitBackend` | `avakill.core.rate_limit_store` | Protocol for persistent rate-limit storage |

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full architecture overview.
