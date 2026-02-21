# MCP Proxy: Universal Agent Interception

AvaKill's MCP proxy intercepts all tool calls between any MCP-capable agent and its MCP servers. One command wraps your agent configs — no code changes required.

## How It Works

```
Agent (Claude Desktop, Cursor, Windsurf, Cline, Continue.dev)
  │
  ├─ tools/call: read_file({path: "/etc/passwd"})
  │
  ▼
AvaKill MCP Proxy
  │
  ├─ Evaluate against policy → deny
  ├─ Return MCP error response to agent
  │
  ▼
Upstream MCP Server (never sees the call)
```

AvaKill rewrites your agent's MCP config so every server command routes through `avakill mcp-proxy`. The proxy sits between the agent and the real server, intercepting `tools/call` JSON-RPC messages and evaluating them against your policy.

## Quick Start

```bash
# 1. Wrap all detected agent configs
avakill mcp-wrap --policy avakill.yaml

# 2. Verify (dry run)
avakill mcp-wrap --dry-run

# 3. Undo wrapping
avakill mcp-unwrap
```

## Supported Agents

| Agent | Config Location (macOS) | Config Location (Linux) |
|-------|------------------------|------------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/claude/claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` or `~/.cursor/mcp.json` | `.cursor/mcp.json` or `~/.cursor/mcp.json` |
| Windsurf | `.windsurf/mcp.json` or `~/.codeium/windsurf/mcp.json` | Same |
| Cline | `.vscode/cline_mcp_settings.json` | Same |
| Continue.dev | `.continue/config.json` | Same |

## Step-by-Step Setup

### Claude Desktop

```bash
# Wrap Claude Desktop's MCP config
avakill mcp-wrap --agent claude-desktop --policy avakill.yaml

# Verify the config was rewritten
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Restart Claude Desktop to pick up the changes
```

**Before:**
```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-fs", "/path"]
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "fs": {
      "command": "avakill",
      "args": ["mcp-proxy", "--policy", "avakill.yaml",
               "--upstream-cmd", "npx",
               "--upstream-args", "-y @anthropic/mcp-fs /path"]
    }
  }
}
```

### Cursor / Windsurf / Cline

```bash
# Wrap a specific agent
avakill mcp-wrap --agent cursor --policy avakill.yaml

# Or wrap all detected agents at once
avakill mcp-wrap --agent all --policy avakill.yaml
```

## HTTP Proxy Mode

For MCP servers that use Streamable HTTP transport instead of stdio:

```bash
avakill mcp-proxy --upstream-url http://localhost:3000/mcp --listen-port 5100 --policy avakill.yaml
```

The HTTP proxy intercepts `tools/call` POST requests the same way the stdio proxy intercepts JSON-RPC messages.

Requires the `mcp-http` extra:

```bash
pip install avakill[mcp-http]
```

## Evaluation Modes

### Embedded Guard (default)

The proxy loads the policy file and evaluates tool calls in-process.

```bash
avakill mcp-proxy --upstream-cmd npx --upstream-args "-y @anthropic/mcp-fs" --policy avakill.yaml
```

### Daemon Mode

The proxy delegates evaluation to a running AvaKill daemon. This enables shared policy, centralized audit logging, and hot-reload.

```bash
# Start the daemon
avakill daemon start --policy avakill.yaml

# Wrap with daemon mode
avakill mcp-wrap --agent all --daemon

# Or run the proxy directly
avakill mcp-proxy --upstream-cmd npx --upstream-args "..." --daemon ~/.avakill/avakill.sock
```

### Standalone Mode

For per-project setups without a daemon:

```bash
avakill mcp-proxy --upstream-cmd npx --upstream-args "..." --policy ./project-policy.yaml
```

## Tool Normalization

When the `--agent` flag is set, MCP tool names are normalized to canonical names before policy evaluation. This means a single policy works across all agents:

```yaml
policies:
  - name: deny-shell
    tools: ["shell_execute"]
    action: deny
```

This policy blocks `Bash` (Claude Code), `run_shell_command` (Gemini CLI), `shell_command` (Cursor), and `run_command` (Windsurf) — all normalized to `shell_execute`.

## Troubleshooting

### Restore Original Configs

```bash
# Unwrap all agents
avakill mcp-unwrap --agent all

# Or restore from backup
cp ~/Library/Application\ Support/Claude/claude_desktop_config.json.bak \
   ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Check Wrapped Status

```bash
# Dry run shows current wrap status
avakill mcp-wrap --dry-run
```

### Agent Not Detecting Wrapped Config

Restart the agent after wrapping. Most agents load MCP configs at startup.

### MCP Server Fails to Start

Check that `avakill` is on the PATH. The wrapped config invokes `avakill mcp-proxy`, which must be resolvable:

```bash
which avakill  # Should show the installed path
```

### Audit Logs Not Appearing

In daemon mode, audit events are emitted locally by the proxy. In embedded mode, the Guard handles audit logging. Ensure `--log-db` is set or the daemon is configured with a logger.
