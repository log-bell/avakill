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
    normalize_tools: bool = False,
    approval_store: ApprovalStore | None = None,
    cross_call_correlation: bool = False,
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
| `normalize_tools` | `bool` | `False` | Enable automatic tool name normalization via ToolNormalizer |
| `approval_store` | `ApprovalStore \| None` | `None` | Approval store for `require_approval` action. If `None`, approval requests are not persisted. |
| `cross_call_correlation` | `bool` | `False` | Enable cross-call correlation for session-level behavioral analysis |

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
    override: bool = False,
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
| `override` | If `True` and the decision is `overridable`, flip deny to allow with `[override]` audit trail |

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
| `overridable` | `bool` | Whether this denial can be overridden (based on rule enforcement level) |

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
| `recovery_hint` | `Any \| None` | Recovery guidance attached by `avakill fix` |

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
)
await proxy.run()
```

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

## avakill.DaemonServer

Persistent Unix domain socket server for evaluating tool calls. Used by agent hooks and the `avakill evaluate` CLI command.

### Constructor

```python
DaemonServer(
    guard: Guard,
    socket_path: str | Path | None = None,
    pid_file: str | Path | None = None,
    normalizer: ToolNormalizer | None = None,
    max_connections: int = 100,
    transport: ServerTransport | None = None,
    tcp_port: int | None = None,
    os_enforce: bool = False,
    on_ready: Callable[[str], None] | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `guard` | `Guard` | *(required)* | Guard instance for policy evaluation |
| `socket_path` | `str \| Path \| None` | `None` | Unix socket path. Defaults to `AVAKILL_SOCKET` env var or `~/.avakill/avakill.sock`. |
| `pid_file` | `str \| Path \| None` | `None` | PID file path. Defaults to `~/.avakill/avakill.pid`. |
| `normalizer` | `ToolNormalizer \| None` | `None` | Tool name normalizer for agent-specific tool names |
| `max_connections` | `int` | `100` | Maximum concurrent connections |
| `transport` | `ServerTransport \| None` | `None` | Custom transport layer |
| `tcp_port` | `int \| None` | `None` | Optional TCP port (in addition to Unix socket) |
| `os_enforce` | `bool` | `False` | Enable OS-level enforcement backends |
| `on_ready` | `Callable[[str], None] \| None` | `None` | Callback invoked after the server starts, receives the socket path |

### start()

```python
await DaemonServer.start() -> None
```

Create the Unix socket, install signal handlers (SIGHUP for reload, SIGTERM/SIGINT for shutdown), and begin accepting connections.

### stop()

```python
await DaemonServer.stop() -> None
```

Close the server, clean up socket and PID files.

### serve_forever()

```python
await DaemonServer.serve_forever() -> None
```

Start and block until a stop signal is received.

### is_running()

```python
@staticmethod
DaemonServer.is_running(pid_file: str | Path | None = None) -> tuple[bool, int | None]
```

Check if a daemon is running. Returns `(True, pid)` or `(False, None)`.

---

## avakill.DaemonClient

Synchronous client for communicating with the AvaKill daemon. Designed for short-lived hook scripts.

### Constructor

```python
DaemonClient(
    socket_path: str | Path | None = None,
    timeout: float = 5.0,
    transport: ClientTransport | None = None,
    tcp_port: int | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `socket_path` | `str \| Path \| None` | `None` | Unix socket path. Defaults to `AVAKILL_SOCKET` env var or `~/.avakill/avakill.sock`. |
| `timeout` | `float` | `5.0` | Connection and read timeout in seconds |
| `transport` | `ClientTransport \| None` | `None` | Custom transport layer |
| `tcp_port` | `int \| None` | `None` | Connect via TCP instead of Unix socket |

### evaluate()

```python
DaemonClient.evaluate(request: EvaluateRequest) -> EvaluateResponse
```

Send an evaluation request to the daemon. **Fail-closed:** returns a deny response on any error (connection refused, timeout, parse failure).

### ping()

```python
DaemonClient.ping() -> bool
```

Check daemon connectivity. Returns `True` if the daemon responds.

### try_evaluate()

```python
DaemonClient.try_evaluate(request: EvaluateRequest) -> EvaluateResponse | None
```

Like `evaluate()` but returns `None` on connection failure instead of a deny response.

---

## Wire Protocol Models

Available from `avakill.daemon.protocol`.

### EvaluateRequest

```python
from avakill.daemon.protocol import EvaluateRequest

request = EvaluateRequest(
    agent="claude-code",
    tool="Bash",
    args={"command": "rm -rf /"},
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | `int` | `1` | Protocol version |
| `agent` | `str` | *(required)* | Agent identifier (e.g., `"claude-code"`, `"gemini-cli"`, `"cli"`) |
| `event` | `str` | `"pre_tool_use"` | Hook event name |
| `tool` | `str` | *(required)* | Agent-native tool name |
| `args` | `dict[str, Any]` | `{}` | Tool arguments |
| `context` | `dict[str, Any]` | `{}` | Additional context |

### EvaluateResponse

```python
from avakill.daemon.protocol import EvaluateResponse
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `decision` | `Literal["allow", "deny", "require_approval"]` | *(required)* | The policy decision |
| `reason` | `str \| None` | `None` | Human-readable explanation |
| `policy` | `str \| None` | `None` | Name of the matching policy rule |
| `latency_ms` | `float` | `0.0` | Evaluation time in milliseconds |
| `modified_args` | `dict[str, Any] \| None` | `None` | Modified arguments (reserved) |
| `approval_request_id` | `str \| None` | `None` | UUID of the pending approval request (when decision is `require_approval`) |

### Serialization

```python
from avakill.daemon.protocol import (
    serialize_request, deserialize_request,
    serialize_response, deserialize_response,
)

# Newline-delimited JSON over Unix socket
data = serialize_request(request)    # -> bytes
req = deserialize_request(data)      # -> EvaluateRequest
data = serialize_response(response)  # -> bytes
resp = deserialize_response(data)    # -> EvaluateResponse
```

---

## avakill.ToolNormalizer

Translates agent-specific tool names to canonical names for universal policy evaluation.

Available from `avakill.core.normalization`.

### Constructor

```python
ToolNormalizer(custom_mappings: dict[str, dict[str, str]] | None = None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `custom_mappings` | `dict[str, dict[str, str]] \| None` | `None` | Additional agent-to-canonical mappings merged with built-in ones |

### normalize()

```python
ToolNormalizer.normalize(tool: str, agent: str | None = None) -> str
```

Translate an agent-native tool name to its canonical name. Returns the original name if no mapping exists.

```python
normalizer = ToolNormalizer()
normalizer.normalize("Bash", agent="claude-code")       # → "shell_execute"
normalizer.normalize("run_shell_command", agent="gemini-cli")  # → "shell_execute"
normalizer.normalize("unknown_tool", agent="claude-code")      # → "unknown_tool"
```

### denormalize()

```python
ToolNormalizer.denormalize(canonical: str, agent: str) -> str | None
```

Reverse lookup: canonical name to agent-native name. Returns `None` if no mapping exists.

### AGENT_TOOL_MAP

Built-in mapping of agent-native tool names to canonical names:

| Agent | Native Name | Canonical Name |
|-------|------------|----------------|
| `claude-code` | `Bash` | `shell_execute` |
| `claude-code` | `Read` | `file_read` |
| `claude-code` | `Write` | `file_write` |
| `claude-code` | `Edit` / `MultiEdit` | `file_edit` |
| `claude-code` | `Glob` | `file_search` |
| `claude-code` | `Grep` | `content_search` |
| `claude-code` | `WebFetch` | `web_fetch` |
| `claude-code` | `WebSearch` | `web_search` |
| `claude-code` | `Task` | `agent_spawn` |
| `claude-code` | `LS` | `file_list` |
| `gemini-cli` | `run_shell_command` | `shell_execute` |
| `gemini-cli` | `read_file` | `file_read` |
| `gemini-cli` | `write_file` | `file_write` |
| `gemini-cli` | `edit_file` | `file_edit` |
| `gemini-cli` | `search_files` | `file_search` |
| `gemini-cli` | `list_files` | `file_list` |
| `gemini-cli` | `web_search` | `web_search` |
| `gemini-cli` | `web_fetch` | `web_fetch` |
| `cursor` | `shell_command` | `shell_execute` |
| `cursor` | `read_file` | `file_read` |
| `windsurf` | `run_command` | `shell_execute` |
| `windsurf` | `write_code` | `file_write` |
| `windsurf` | `read_code` | `file_read` |
| `windsurf` | `mcp_tool` | `mcp_tool` |
| `openai-codex` | `shell` / `shell_command` / `local_shell` / `exec_command` | `shell_execute` |
| `openai-codex` | `apply_patch` | `file_write` |
| `openai-codex` | `read_file` | `file_read` |
| `openai-codex` | `list_dir` | `file_list` |
| `openai-codex` | `grep_files` | `content_search` |

MCP tool names (prefixed with `mcp__` or `mcp:`) pass through without normalization.

---

## avakill.PolicyCascade

Discovers and merges policy files from multiple levels. Available from `avakill.core.cascade`.

### discover()

```python
PolicyCascade.discover(cwd: Path | None = None) -> list[tuple[PolicyLevel, Path]]
```

Find all policy files in discovery order. `PolicyLevel` is `Literal["system", "global", "project", "local"]`.

**Discovery paths (in priority order):**

| Level | Path | Description |
|-------|------|-------------|
| System | `/etc/avakill/policy.yaml` | Organization-wide defaults (admin-managed) |
| Global | `~/.config/avakill/policy.yaml` | User-wide defaults |
| Project | `.avakill/policy.yaml`, `avakill.yaml`, or `avakill.yml` | Project-specific (walks up directory tree) |
| Local | `.avakill/policy.local.yaml` | Local overrides (gitignored) |

### load()

```python
PolicyCascade.load(cwd: Path | None = None) -> PolicyConfig
```

Discover, load, and merge all policy files into a single `PolicyConfig`.

### merge()

```python
@staticmethod
PolicyCascade.merge(configs: list[PolicyConfig]) -> PolicyConfig
```

Merge multiple configs with **deny-wins semantics**:
- Default action: `"deny"` if any level says deny
- Deny rules: union across all levels
- Allow rules: kept only if no higher-level hard-deny overrides them
- Rate limits: most restrictive (lowest `max_calls`) wins
- Hard enforcement at a higher level cannot be relaxed by lower levels

---

## Hook Adapters

Available from `avakill.hooks`. Each adapter translates agent-specific hook payloads into `EvaluateRequest` objects.

### HookAdapter (base class)

```python
from avakill.hooks.base import HookAdapter
```

Abstract base class for all hook adapters.

| Method | Description |
|--------|-------------|
| `agent_name: str` | Class attribute identifying the agent |
| `parse_stdin(raw: str) -> EvaluateRequest` | Parse agent's stdin payload into a request |
| `format_response(response: EvaluateResponse) -> tuple[str \| None, int]` | Format response as `(stdout_content, exit_code)` |
| `run(stdin_data: str \| None = None)` | Main entry point: read stdin, evaluate, write response |

### Built-in Adapters

| Adapter | Agent | Hook Event | Deny Signal |
|---------|-------|-----------|-------------|
| `ClaudeCodeAdapter` | `claude-code` | PreToolUse | `permissionDecision: "deny"` in JSON |
| `GeminiCliAdapter` | `gemini-cli` | BeforeTool | `permissionDecision: "deny"` in JSON |
| `CursorAdapter` | `cursor` | beforeShellExecution | `continue: false` in JSON (always exit 0) |
| `WindsurfAdapter` | `windsurf` | pre_run_command | Exit code 2 + reason on stderr |
| `OpenAICodexAdapter` | `openai-codex` | before_tool_use | Exit code 1 + JSON `{"decision": "block"}` |

Each adapter has a corresponding console script entry point: `avakill-hook-claude-code`, `avakill-hook-gemini-cli`, `avakill-hook-cursor`, `avakill-hook-windsurf`, `avakill-hook-openai-codex`.

**Standalone mode:** If the daemon is unreachable, adapters fall back to standalone evaluation using the policy file at `AVAKILL_POLICY` environment variable.

---

## Enforcement Backends

Available from `avakill.enforcement`.

### LandlockEnforcer

Linux 5.13+ unprivileged filesystem access restrictions.

```python
from avakill.enforcement.landlock import LandlockEnforcer

# Check availability
LandlockEnforcer.available()  # → True on Linux 5.13+

enforcer = LandlockEnforcer()

# Dry run — see what would be restricted
ruleset = enforcer.generate_ruleset(policy_config)

# Apply — IRREVERSIBLE for the current process
enforcer.apply(policy_config)
```

### SandboxExecEnforcer

macOS Seatbelt Profile Language (SBPL) generation.

```python
from avakill.enforcement.sandbox_exec import SandboxExecEnforcer

# Check availability
SandboxExecEnforcer.available()  # → True on macOS

enforcer = SandboxExecEnforcer()

# Generate SBPL profile string
profile = enforcer.generate_profile(policy_config)

# Write to file
enforcer.write_profile(policy_config, Path("avakill.sb"))
```

### TetragonPolicyGenerator

Cilium Tetragon Kubernetes TracingPolicy generation.

```python
from avakill.enforcement.tetragon import TetragonPolicyGenerator

generator = TetragonPolicyGenerator()

# Generate TracingPolicy YAML
yaml_str = generator.generate(policy_config)

# With optional parameters
yaml_str = generator.generate(policy_config, match_binaries=["/usr/bin/python3"], action="Sigkill")

# Write to file
generator.write(policy_config, Path("tetragon-policy.yaml"))
```

---

## Compliance & Approvals

### ComplianceAssessor

Automated compliance assessment. Available from `avakill.compliance.assessor`.

```python
from avakill.compliance.assessor import ComplianceAssessor

assessor = ComplianceAssessor(guard=guard, logger=logger)

# Assess single framework
report = assessor.assess("soc2")

# Assess all frameworks
reports = assessor.assess_all()  # → dict[str, ComplianceReport]
```

**Supported frameworks:**

| Framework | ID | Controls |
|-----------|-----|----------|
| SOC 2 Type II | `soc2` | CC6.1, CC6.3, CC7.1, CC7.2, CC8.1 |
| NIST AI RMF | `nist-ai-rmf` | GOVERN, MAP, MEASURE, MANAGE |
| EU AI Act | `eu-ai-act` | Art.9, Art.12, Art.14 |
| ISO 42001 | `iso-42001` | A.2.3, A.5, A.6, A.7, A.8 |

### ComplianceReporter

Format compliance reports. Available from `avakill.compliance.reporter`.

```python
from avakill.compliance.reporter import ComplianceReporter

reporter = ComplianceReporter()
table = reporter.to_rich_table(report)  # Rich Table for terminal
json_str = reporter.to_json(report)     # JSON string
md_str = reporter.to_markdown(report)   # Markdown string
```

### ApprovalStore

SQLite-backed approval workflow. Available from `avakill.core.approval`.

```python
from avakill.core.approval import ApprovalStore

async with ApprovalStore("approvals.db") as store:
    # Create approval request (default TTL: 1 hour)
    request = await store.create(tool_call, decision, agent="claude-code", ttl_seconds=3600)

    # List pending
    pending = await store.get_pending()

    # Approve or deny
    approved = await store.approve(request.id, approver="admin")
    denied = await store.deny(request.id, approver="admin")

    # Clean up expired
    count = await store.cleanup_expired()

    # Find approved request for tool+agent
    req = await store.get_approved_for_tool("shell_execute", agent="claude-code")

    # Resolve a prefix ID (12-char) to full UUID
    full_id = await store.resolve_id("abc123def456")

    # Get a single request by ID
    req = await store.get(request.id)

    # Close the database connection
    await store.close()
```

### AuditAnalytics

Audit log analysis engine. Available from `avakill.analytics.engine`.

```python
from avakill.analytics.engine import AuditAnalytics

analytics = AuditAnalytics(logger=sqlite_logger)

# Denial trends (time-bucketed)
trends = await analytics.denial_trend(hours=24, bucket_minutes=60)

# Per-tool usage summary
usage = await analytics.tool_usage_summary()  # → {"tool": {"allowed": N, "denied": N}}

# Per-agent risk scores (0.0 = safe, 1.0 = all denied)
scores = await analytics.agent_risk_scores()

# Per-rule effectiveness
effectiveness = await analytics.policy_effectiveness()
```

---

## avakill.ProcessLauncher

Launches and manages sandboxed child processes. Available from `avakill.launcher.core`. Exported in `__all__`.

```python
from avakill.launcher.core import ProcessLauncher
```

> **Note:** ProcessLauncher is shipped but currently untested per audit status.

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
| `DaemonServer` | `avakill.daemon.server` | Unix domain socket server for persistent evaluation |
| `DaemonClient` | `avakill.daemon.client` | Synchronous client for hook scripts |
| `ToolNormalizer` | `avakill.core.normalization` | Agent-native to canonical tool name translation |
| `PolicyCascade` | `avakill.core.cascade` | Multi-level policy discovery and merge |
| `HookAdapter` | `avakill.hooks.base` | Abstract base class for agent hook adapters |
| `LandlockEnforcer` | `avakill.enforcement.landlock` | Linux Landlock filesystem restrictions |
| `SandboxExecEnforcer` | `avakill.enforcement.sandbox_exec` | macOS SBPL profile generation |
| `TetragonPolicyGenerator` | `avakill.enforcement.tetragon` | Cilium Kubernetes TracingPolicy generation |
| `ComplianceAssessor` | `avakill.compliance.assessor` | Automated compliance framework assessment |
| `ComplianceReporter` | `avakill.compliance.reporter` | Compliance report formatting (table/JSON/Markdown) |
| `ApprovalStore` | `avakill.core.approval` | SQLite-backed approval workflow |
| `AuditAnalytics` | `avakill.analytics.engine` | Audit log analysis and risk scoring |
| `ProcessLauncher` | `avakill.launcher.core` | Sandboxed child process launcher (shipped-untested) |

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full architecture overview.
