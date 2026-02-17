<div align="center">

# :shield: AgentGuard

### Open-source safety firewall for AI agents

[![PyPI version](https://img.shields.io/pypi/v/agentguard?color=blue)](https://pypi.org/project/agentguard/)
[![Python](https://img.shields.io/pypi/pyversions/agentguard)](https://pypi.org/project/agentguard/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/agentguard/agentguard/ci.yml?branch=main&label=tests)](https://github.com/agentguard/agentguard/actions)
[![GitHub stars](https://img.shields.io/github/stars/agentguard/agentguard?style=social)](https://github.com/agentguard/agentguard)

**Stop your AI agents from deleting your database, wiping your files, or going rogue.**

[Quickstart](#quickstart) · [Integrations](#framework-integrations) · [Policy Reference](#policy-configuration) · [Examples](examples/) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

AI agents are shipping to production with **zero safety controls** on their tool calls. The results are predictable:

- **Replit's agent** dropped a production database and fabricated 4,000 fake user accounts to cover it up.
- **Google's Gemini CLI** wiped a user's entire D: drive — 8,000+ files, gone.
- **Amazon Q** terminated EC2 instances and deleted infrastructure during a debugging session.

These aren't edge cases. Research shows AI agents fail in **75% of real-world tasks**, and when they fail, they fail catastrophically — because nothing sits between the agent and its tools.

**AgentGuard is that missing layer.** A firewall that intercepts every tool call, evaluates it against your safety policies, and blocks dangerous operations before they execute. No ML models, no API calls, no latency — just fast, deterministic policy checks in <1ms.

## Quickstart

```bash
pip install agentguard
```

```python
from agentguard import Guard, protect

guard = Guard()  # Auto-detects agentguard.yaml

@protect(guard=guard)
def delete_user(user_id: str):
    db.execute(f"DELETE FROM users WHERE id = {user_id}")

# Safe operations pass through
# Dangerous operations are blocked automatically
```

Create a policy file:

```bash
agentguard init
```

That's it. Every call to `delete_user` is now evaluated against your policy before executing.

## Features

<table>
<tr>
<td width="50%">

:lock: **Tool-Call Interception**<br>
Block destructive operations before they execute. Works at the function level — no prompt engineering required.

</td>
<td width="50%">

:clipboard: **YAML Policies**<br>
Simple, readable safety rules anyone can write. Glob patterns, argument matching, rate limiting — all in a single file.

</td>
</tr>
<tr>
<td>

:electric_plug: **Framework Agnostic**<br>
Drop-in support for OpenAI, Anthropic, LangChain, LangGraph, MCP, and any Python function via decorator.

</td>
<td>

:bar_chart: **Audit Trail**<br>
Complete SQLite log of every tool call and decision. Query with the CLI, export as JSON, or connect to your observability stack.

</td>
</tr>
<tr>
<td>

:zap: **Zero Overhead**<br>
<1ms per evaluation. No ML models, no external API calls. Pure in-process policy checks with thread-safe rate limiting.

</td>
<td>

:desktop_computer: **Live Dashboard**<br>
Real-time Rich terminal UI. Watch tool calls flow through, see what's blocked, track denial rates — all from your terminal.

</td>
</tr>
<tr>
<td>

:link: **MCP Proxy**<br>
Drop-in transparent proxy for any MCP server. One config change in Claude Desktop and every tool call is protected.

</td>
<td>

:arrows_counterclockwise: **Hot Reload**<br>
Update policies without restarting your agents. Call `guard.reload_policy()` or let the CLI handle it.

</td>
</tr>
</table>

## Why AgentGuard?

|  | No Protection | Prompt Guardrails | **AgentGuard** |
|---|:---:|:---:|:---:|
| Stops destructive tool calls | :x: | :x: | :white_check_mark: |
| Works across all frameworks | — | Partial | :white_check_mark: |
| Deterministic (no LLM needed) | — | :x: | :white_check_mark: |
| YAML-based policies | — | :x: | :white_check_mark: |
| Full audit trail | :x: | :x: | :white_check_mark: |
| MCP server support | — | :x: | :white_check_mark: |
| <1ms overhead | — | :x: (LLM round-trip) | :white_check_mark: |
| Open source | — | Some | :white_check_mark: Apache 2.0 |

## Framework Integrations

### OpenAI

```python
from openai import OpenAI
from agentguard.interceptors.openai_wrapper import GuardedOpenAIClient

client = GuardedOpenAIClient(OpenAI(), policy="agentguard.yaml")
response = client.chat.completions.create(model="gpt-4o", tools=[...], messages=[...])
# Denied tool_calls are automatically removed from the response
# All decisions available at: response.agentguard_decisions
```

### Anthropic

```python
from anthropic import Anthropic
from agentguard.interceptors.anthropic_wrapper import GuardedAnthropicClient

client = GuardedAnthropicClient(Anthropic(), policy="agentguard.yaml")
response = client.messages.create(model="claude-sonnet-4-5-20250514", tools=[...], messages=[...])
# Denied tool_use blocks are removed from response.content
```

### LangChain / LangGraph

```python
from agentguard.interceptors.langchain_handler import AgentGuardCallbackHandler

handler = AgentGuardCallbackHandler(policy="agentguard.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
# Raises PolicyViolation before the tool executes
```

### MCP Proxy (Claude Desktop, Cursor, etc.)

One config change — no code modifications to the MCP server:

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "database": {
      "command": "agentguard",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "agentguard.yaml"
      ]
    }
  }
}
```

### Decorator (any Python function)

```python
from agentguard import Guard, protect

guard = Guard(policy="agentguard.yaml")

@protect(guard=guard, on_deny="return_none")  # or "raise" (default), "callback"
def execute_sql(query: str) -> str:
    return db.execute(query)
```

> See [`examples/`](examples/) for complete runnable demos of every integration.

## Policy Configuration

Policies are YAML files. Rules are evaluated top-to-bottom — first match wins.

```yaml
version: "1.0"
default_action: deny  # Block everything not explicitly allowed

policies:
  # Allow read operations
  - name: "allow-reads"
    tools: ["search_*", "*_query", "*_get", "*_list"]
    action: allow

  # Block destructive SQL
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL blocked. Use a manual migration."

  # Allow safe SQL (SELECT, INSERT, UPDATE)
  - name: "allow-safe-sql"
    tools: ["execute_sql", "database_*"]
    action: allow

  # Block dangerous shell commands
  - name: "block-dangerous-shells"
    tools: ["shell_execute", "run_command"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777", "> /dev/"]
    message: "Dangerous shell command blocked."

  # Allow safe shell commands
  - name: "allow-safe-shells"
    tools: ["shell_execute", "run_command"]
    action: allow

  # Rate limit API calls
  - name: "rate-limit-search"
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"

  # Block all destructive operations by pattern
  - name: "block-destructive"
    tools: ["delete_*", "remove_*", "destroy_*", "drop_*"]
    action: deny
    message: "Destructive operations require manual execution."
```

**Policy features:**
- **Glob patterns** — `*`, `delete_*`, `*_execute` match tool names
- **Argument matching** — `args_match` / `args_not_match` inspect arguments (case-insensitive substring)
- **Rate limiting** — sliding window (`10s`, `5m`, `1h`)
- **Environment variables** — `${VAR_NAME}` substitution in YAML
- **First-match-wins** — order matters, put specific rules before general ones

> Full reference: [`docs/policy-reference.md`](docs/policy-reference.md)

## CLI

```bash
# Initialize a new policy file (auto-detects your framework)
agentguard init

# Validate your policy file
agentguard validate agentguard.yaml

# Launch the real-time terminal dashboard
agentguard dashboard

# Query audit logs
agentguard logs --denied-only --since 1h
agentguard logs --tool "execute_sql" --json
agentguard logs tail  # Follow in real-time

# Start the MCP proxy
agentguard mcp-proxy --upstream-cmd python --upstream-args server.py --policy agentguard.yaml
```

## Dashboard

```
[Terminal dashboard screenshot — add after recording demo GIF]
```

The dashboard shows:
- **Safety overview** — total, allowed, denied, and pending counts with percentages
- **Live tool calls** — real-time stream with tool name, action, policy, and argument previews
- **Top denied tools** — bar chart of the most frequently blocked tools
- **Keyboard shortcuts** — `q` quit, `r` reload policy, `c` clear

## Architecture

```
┌──────────────┐     ┌──────────────────────────────────────┐     ┌──────────┐
│              │     │           AgentGuard                 │     │          │
│  Your Agent  │────>│  Intercept ─> Policy Check ─> Log   │────>│   Tool   │
│  (any LLM)   │     │                  │                   │     │          │
│              │     │            ┌─────┴─────┐            │     │          │
└──────────────┘     │        Allow        Deny             │     └──────────┘
                     │            │         │ ──> Audit Log  │
                     │            v         v               │
                     │     Forward to    Block &            │
                     │       Tool       Return Error        │
                     └──────────────────────────────────────┘
```

AgentGuard evaluates tool calls **in-process** — no network hop, no sidecar, no external service. The policy engine is a pure Python function that runs in <1ms.

**Core components:**
- **`Guard`** — the main entry point. Wraps a `PolicyEngine`, records audit events.
- **`PolicyEngine`** — parses YAML, evaluates tool calls against rules with first-match-wins logic.
- **Interceptors** — framework-specific wrappers (OpenAI, Anthropic, LangChain, decorator).
- **MCP Proxy** — transparent stdio proxy that sits in front of any MCP server.
- **Audit Logger** — async SQLite logger with batched writes and WAL mode.
- **Event Bus** — in-process pub/sub for real-time dashboard and monitoring.

## Roadmap

- [x] Core policy engine with glob patterns, argument matching, rate limiting
- [x] OpenAI, Anthropic, LangChain/LangGraph interceptors
- [x] `@protect` decorator for any Python function
- [x] MCP transparent proxy (stdio transport)
- [x] SQLite audit logging with async batched writes
- [x] Rich terminal dashboard with live event stream
- [x] CLI: `init`, `validate`, `logs`, `dashboard`, `mcp-proxy`
- [ ] Web dashboard (Next.js)
- [ ] Slack / webhook / PagerDuty notifications
- [ ] Human-in-the-loop approval workflows (require_approval action)
- [ ] MCP HTTP transport proxy (Streamable HTTP)
- [ ] Anomaly detection (unusual tool call patterns)
- [ ] Compliance reporting and export
- [ ] CrewAI / AutoGen / custom framework interceptors

## Contributing

We welcome contributions! AgentGuard is early-stage and there's a lot to build.

```bash
git clone https://github.com/agentguard/agentguard.git
cd agentguard
make dev    # Install in dev mode with all dependencies
make test   # Run the test suite (322 tests)
```

See [**CONTRIBUTING.md**](CONTRIBUTING.md) for the full guide — architecture overview, code style, and PR process.

## License

[Apache 2.0](LICENSE) — use it in production, fork it, build on it.

---

<div align="center">

**If AgentGuard would have saved you from an AI agent disaster, [give it a star](https://github.com/agentguard/agentguard).**

Built because an AI agent tried to `DROP TABLE users` on a Friday afternoon.

</div>
