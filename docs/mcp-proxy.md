# MCP Proxy

AvaKill's MCP proxy is a transparent man-in-the-middle that sits between an MCP client (Claude Desktop, Cursor, Claude Code, or any custom host) and an upstream MCP server. It intercepts `tools/call` requests, evaluates them against your policy, and kills anything that violates it — all without modifying the upstream server or the client.

## Architecture

```
┌─────────────────────┐          ┌──────────────────────────────┐          ┌──────────────────┐
│                     │  stdin   │                              │  stdin   │                  │
│    MCP Client       │ ──────→ │    AvaKill MCP Proxy       │ ──────→ │  Upstream MCP    │
│  (Claude Desktop,   │          │                              │          │     Server       │
│   Cursor, etc.)     │ ←────── │  ┌────────────────────────┐  │ ←────── │  (your server)   │
│                     │  stdout  │  │   Policy Engine        │  │  stdout  │                  │
└─────────────────────┘          │  │                        │  │          └──────────────────┘
                                 │  │  avakill.yaml       │  │
                                 │  │  ┌──────────────────┐  │  │
                                 │  │  │ tools/call?      │  │  │
                                 │  │  │                  │  │  │
                                 │  │  │ allowed → forward│  │  │
                                 │  │  │ denied  → block  │  │  │
                                 │  │  └──────────────────┘  │  │
                                 │  └────────────────────────┘  │
                                 │                              │
                                 │  ┌────────────────────────┐  │
                                 │  │ Audit Logger (optional)│  │
                                 │  │ SQLite: audit.db       │  │
                                 │  └────────────────────────┘  │
                                 └──────────────────────────────┘
```

## How It Works

1. **The proxy replaces the server command.** Instead of the MCP client launching the upstream server directly, it launches the AvaKill proxy. The proxy then spawns the upstream server as a child process.

2. **Bidirectional stdio relay.** The proxy reads JSON-RPC messages from the client's stdin, processes them, and writes them to the upstream server's stdin. Responses from the upstream's stdout flow back to the client's stdout. Stderr from the upstream is captured and logged.

3. **Selective interception.** Only `tools/call` requests are inspected. Every other MCP method (`tools/list`, `resources/read`, `prompts/get`, notifications, etc.) passes through unchanged with zero overhead.

4. **Policy evaluation.** When a `tools/call` arrives, the proxy extracts the tool name and arguments from the JSON-RPC params, calls `guard.evaluate()`, and checks the decision:
   - **Allowed**: the original request is forwarded to the upstream server.
   - **Denied**: a synthetic MCP error response is sent directly to the client. The upstream server never sees the request.

5. **Transparent to both sides.** The client doesn't know there's a proxy. The upstream server doesn't know there's a proxy. Tool schemas, capabilities, and all other metadata flow through unchanged.

## Setup: stdio Transport

The MCP proxy currently supports **stdio transport** — the standard MCP communication method where client and server exchange JSON-RPC messages over stdin/stdout.

### 1. Install AvaKill

```bash
pip install avakill
```

### 2. Create a policy file

Create `avakill.yaml` with rules for the tools your MCP server exposes:

```yaml
version: "1.0"
default_action: deny

policies:
  - name: allow-reads
    tools: ["*_read", "*_get", "*_list", "*_search"]
    action: allow

  - name: block-destructive
    tools: ["*_delete", "*_drop", "*_destroy"]
    action: deny
    message: "Destructive operations blocked by AvaKill"

  - name: block-dangerous-sql
    tools: ["execute_sql", "query"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE"]
    message: "Destructive SQL blocked"

  - name: allow-safe-sql
    tools: ["execute_sql", "query"]
    action: allow

  - name: rate-limit-search
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "1m"
```

### 3. Start the proxy

#### CLI

```bash
avakill mcp-proxy \
  --upstream-cmd python \
  --upstream-args "my_mcp_server.py" \
  --policy avakill.yaml
```

The proxy prints a startup banner to stderr (since stdout is the MCP protocol channel):

```
╭──────────────────────────────────────╮
│ AvaKill MCP Proxy                 │
│ Policy:   /path/to/avakill.yaml   │
│ Upstream: python my_mcp_server.py    │
╰──────────────────────────────────────╯
```

#### With audit logging

```bash
avakill mcp-proxy \
  --upstream-cmd python \
  --upstream-args "my_mcp_server.py" \
  --policy avakill.yaml \
  --log-db avakill_audit.db
```

#### Python API

```python
import asyncio
from avakill.core.engine import Guard
from avakill.mcp.proxy import MCPProxyServer

guard = Guard(policy="avakill.yaml")
proxy = MCPProxyServer(
    upstream_cmd="python",
    upstream_args=["my_mcp_server.py"],
    guard=guard,
)

asyncio.run(proxy.start())
```

## Client Configuration

The key insight: you replace the original MCP server command with the AvaKill proxy command. The proxy then launches the original server itself.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your platform.

**Before** (direct connection):

```json
{
  "mcpServers": {
    "my-database": {
      "command": "python",
      "args": ["db_server.py"]
    }
  }
}
```

**After** (through AvaKill):

```json
{
  "mcpServers": {
    "my-database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### Cursor

Edit `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "my-database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "/absolute/path/to/avakill.yaml"
      ]
    }
  }
}
```

Use absolute paths for the policy file — the MCP client may launch the proxy from a different working directory.

### Claude Code

In your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "my-database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### Custom MCP hosts

Any MCP host that supports stdio transport can use the proxy. The pattern is always the same:

1. Replace the server `command` with `avakill`.
2. Set `args` to `["mcp-proxy", "--upstream-cmd", "<original-command>", "--upstream-args", "<original-args>", "--policy", "<policy-path>"]`.
3. The proxy handles everything else.

For upstream servers that take multiple arguments, pass them space-separated in `--upstream-args`:

```json
{
  "command": "avakill",
  "args": [
    "mcp-proxy",
    "--upstream-cmd", "node",
    "--upstream-args", "server.js --port 3000 --verbose",
    "--policy", "avakill.yaml"
  ]
}
```

The `--upstream-args` value is parsed with shell-style splitting (respecting quotes).

## Configuration Reference

### CLI options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--upstream-cmd` | Yes | — | Command to run the upstream MCP server |
| `--upstream-args` | No | `""` | Arguments for the upstream command (space-separated) |
| `--policy` | No | `avakill.yaml` | Path to the policy file |
| `--log-db` | No | `None` | Path to the SQLite audit database. If omitted, no audit logging |

### MCPProxyServer constructor

```python
MCPProxyServer(
    upstream_cmd: str,        # Command to run the upstream server
    upstream_args: list[str], # Arguments as a list
    guard: Guard,             # Configured Guard instance
)
```

## Denied Response Format

When a tool call is denied, the proxy sends a valid MCP response back to the client:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "⛔ AvaKill blocked this tool call: Destructive SQL blocked. Policy: block-dangerous-sql"
      }
    ],
    "isError": true
  }
}
```

The client sees this as a tool execution error, not a protocol error. The AI model receives the error message and can adjust its behavior.

## JSON-RPC Framing

The proxy supports two message framing formats:

1. **Newline-delimited JSON** — the standard MCP stdio encoding. Each message is a single JSON object followed by a newline.
2. **Content-Length header framing** — LSP-style framing used by some MCP implementations. Messages are prefixed with `Content-Length: <n>\r\n\r\n`.

The proxy auto-detects the format per-message, so it works with both styles and can handle mixed framing.

## Streamable HTTP Transport (Planned)

HTTP-based MCP transport is planned for v1.1. The `MCPHTTPProxy` class exists as a placeholder:

```python
from avakill.mcp.proxy import MCPHTTPProxy

proxy = MCPHTTPProxy(
    upstream_url="http://localhost:3000",
    guard=guard,
    host="127.0.0.1",
    port=5100,
)
# await proxy.start()  # Not yet implemented
```

This will listen on a local HTTP port and forward requests to an upstream HTTP MCP server, applying the same policy evaluation to `tools/call` requests.

## Debugging

### Verbose logging

Enable Python logging to see every message flowing through the proxy:

```bash
PYTHONPATH=. python -c "
import logging
import asyncio
logging.basicConfig(level=logging.DEBUG)

from avakill.core.engine import Guard
from avakill.mcp.proxy import MCPProxyServer

guard = Guard(policy='avakill.yaml')
proxy = MCPProxyServer('python', ['my_server.py'], guard)
asyncio.run(proxy.start())
"
```

The `avakill.mcp` logger emits:

| Level | Messages |
|-------|----------|
| `INFO` | Proxy startup and shutdown |
| `WARNING` | Upstream stderr output, JSON-RPC parse failures |
| `ERROR` | Relay task failures, unexpected errors |

### Validate the policy first

Before deploying the proxy, confirm your policy is valid:

```bash
avakill validate avakill.yaml
```

A bad policy file will cause the proxy to exit immediately with a `ConfigError`.

### Test with the dashboard

Run the proxy with `--log-db` and the dashboard side by side:

Terminal 1:
```bash
avakill mcp-proxy \
  --upstream-cmd python --upstream-args "server.py" \
  --policy avakill.yaml --log-db audit.db
```

Terminal 2:
```bash
avakill dashboard --db audit.db
```

You'll see every tool call decision in real-time.

## Common Issues

### "Policy file not found"

The proxy resolves the `--policy` path relative to the working directory at launch time. MCP clients may launch the proxy from an unexpected directory.

**Fix**: use an absolute path for `--policy`:

```json
{
  "args": [
    "mcp-proxy",
    "--policy", "/Users/you/project/avakill.yaml",
    "--upstream-cmd", "python",
    "--upstream-args", "server.py"
  ]
}
```

### "avakill: command not found"

The `avakill` CLI must be on the system PATH used by the MCP client.

**Fix**: use the full path to the `avakill` binary:

```json
{
  "command": "/Users/you/.venv/bin/avakill",
  "args": ["mcp-proxy", "..."]
}
```

Or ensure the virtualenv is activated for the MCP client's environment.

### Proxy exits immediately

Check stderr output. Common causes:

1. **Invalid policy YAML** — run `avakill validate` to check.
2. **Upstream command not found** — verify the `--upstream-cmd` exists and is executable.
3. **Upstream server crashes on startup** — test the upstream server independently first.

### All tool calls are denied

If `default_action: deny` and no rules match the tools your MCP server exposes, everything will be blocked.

**Fix**: check your tool names. Run the upstream server with `tools/list` to see the exact tool names, then write rules that match them.

### Performance: is the proxy slow?

The proxy adds minimal overhead:

- **Message relay**: zero-copy for non-`tools/call` messages. The proxy reads the JSON, checks the `method` field, and forwards immediately.
- **Policy evaluation**: typically < 0.1ms per call. The policy engine uses in-memory pattern matching with `fnmatch`.
- **Rate limiting**: O(1) amortized (deque append/pop).
- **Audit logging**: async fire-and-forget. Writes are batched (up to 50 events or 100ms) and use SQLite WAL mode.

The bottleneck is always the upstream MCP server and the network, not the proxy.

## Graceful Shutdown

The proxy handles `SIGINT` and `SIGTERM`:

1. Cancels the relay tasks (unblocking any pending I/O).
2. Sends `SIGTERM` to the upstream process.
3. Waits up to 5 seconds for the upstream to exit.
4. If the upstream doesn't exit, sends `SIGKILL`.
5. Logs "AvaKill MCP proxy shut down."

`Ctrl+C` in the terminal triggers a clean shutdown.
