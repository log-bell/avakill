# Defense-in-Depth: Layer Composition Guide

AvaKill provides three independent enforcement layers that can be combined for defense-in-depth protection. Each layer addresses different threat vectors, and combining them provides coverage that no single layer can achieve alone.

## Three Enforcement Layers

### 1. Hooks (Cooperative)

The agent voluntarily reports tool calls to AvaKill's daemon via a hook installed in the agent's configuration. The Guard evaluates each call against the policy and returns allow/deny.

**How it works:**
```
Agent -> Hook -> Daemon (Unix socket) -> Guard.evaluate() -> Decision
```

**Strengths:** Semantic, tool-level decisions with argument inspection. Sub-millisecond latency. Works with any agent that supports hooks (Claude Code, Gemini CLI, Cursor, Windsurf).

**Weakness:** Cooperative -- a compromised agent can bypass the hook entirely.

### 2. Launch (OS Sandbox)

AvaKill launches the agent process inside a kernel-enforced sandbox. The sandbox restricts filesystem access, network connections, and executable paths at the OS level.

**How it works:**
```
avakill launch --agent X -> fork() -> Landlock/sandbox_init/AppContainer -> agent
```

**Strengths:** Kernel-enforced -- cannot be bypassed from userspace. Restricts direct syscalls. Works with any agent, no cooperation needed.

**Weakness:** Coarse-grained -- cannot inspect tool call semantics. Path-based, not tool-based.

**Backends:** Landlock (Linux 5.13+), sandbox_init (macOS), AppContainer + Job Objects (Windows).

### 3. MCP Proxy (Universal Interception)

AvaKill sits between an MCP client (the agent) and MCP servers, intercepting every `tools/call` JSON-RPC message. Transparent to both sides.

**How it works:**
```
Agent -> AvaKill MCP Proxy -> Guard.evaluate() -> Upstream MCP Server
```

**Strengths:** Intercepts all MCP tool calls regardless of agent. Inspects tool arguments. Works with any MCP-native agent (Cline, Continue.dev, OpenClaw).

**Weakness:** Only intercepts MCP protocol -- direct filesystem access or subprocess calls bypass it.

## How They Compose

### Hook-Only

Best for: Agents with hook support in trusted environments.

```
+-----------+    hook     +----------+
|   Agent   |------------>|  Daemon  |--> Guard.evaluate()
+-----------+             +----------+
```

Coverage: Tool calls reported by the agent.

### Launch-Only

Best for: Untrusted agents, no hook support, maximum isolation.

```
+-------------------------------+
|  OS Sandbox (Landlock/etc.)   |
|  +-----------+                |
|  |   Agent   |                |
|  +-----------+                |
+-------------------------------+
     restricted paths, network, executables
```

Coverage: All filesystem, network, and process operations.

### MCP-Proxy-Only

Best for: MCP-native agents where you want tool-level inspection without OS sandboxing.

```
+-----------+   MCP    +-------------+   MCP    +--------------+
|   Agent   |--------->|   AvaKill   |--------->|  MCP Server  |
|           |<---------|  MCP Proxy  |<---------|              |
+-----------+          +-------------+          +--------------+
                            |
                     Guard.evaluate()
```

Coverage: All MCP tool calls and their arguments.

### All Three (Maximum Protection)

Best for: High-risk agents in production environments.

```
+----------------------------------------------+
|  OS Sandbox                                   |
|  +-----------+  hook  +----------+            |
|  |   Agent   |------->|  Daemon  |            |
|  |           |        +----------+            |
|  |           |  MCP   +-------------+   MCP   |
|  |           |------->|  MCP Proxy  |-------->| Server
|  +-----------+        +-------------+         |
+----------------------------------------------+
```

Coverage: Triple-layered -- hooks for semantic decisions, OS sandbox for syscall enforcement, MCP proxy for tool call interception.

## Risk Matrix

| Threat | Hooks | OS Sandbox | MCP Proxy | All Three |
|--------|-------|------------|-----------|-----------|
| Unauthorized file write | Deny rule | Path allowlist | tools/call intercept | Triple-covered |
| Network exfiltration | Deny rule | Port allowlist | tools/call intercept | Triple-covered |
| Direct syscall bypass | No | Kernel enforced | No | Sandbox catches |
| Non-MCP tool call | Deny rule | Path/exec restrict | No | Hooks + Sandbox |
| Prompt injection via MCP | No | No | Argument inspection | MCP Proxy |
| Shell command injection | Deny rule + shell_safe | Exec allowlist | tools/call intercept | Triple-covered |
| Process spawning | No | Process limit | No | Sandbox catches |
| Memory exhaustion | No | Memory limit | No | Sandbox catches |
| In-memory attack | No | No | No | Need VM isolation |
| Kernel exploit | No | No | No | Need VM isolation |

## Per-Agent Recommendations

| Agent | Recommended Layers | Rationale |
|-------|-------------------|-----------|
| Claude Code | Hooks + Launch | Native hook support; sandbox for defense-in-depth |
| Gemini CLI | Hooks + Launch | Native hook support; sandbox for defense-in-depth |
| Cursor | Hooks + Launch | Hook support via .cursor/hooks.json |
| Windsurf | Hooks + Launch | Hook support via Codeium config |
| OpenClaw | Launch + MCP Proxy | MCP-native, high-risk, no hook support |
| Aider | Launch only | No hooks, no MCP -- sandbox is the primary defense |
| Cline | MCP Proxy | VS Code extension, MCP-native, cannot be launched externally |
| Continue.dev | MCP Proxy | VS Code extension, MCP-native, cannot be launched externally |
| SWE-Agent | Launch only | Docker-based, no MCP -- sandbox restricts Docker access |

## Usage Examples

### Hook + Launch (Claude Code)

```bash
# Install hooks
avakill hook install --agent claude-code

# Launch with OS sandbox
avakill launch --agent claude-code --policy strict.yaml -- claude
```

### Launch + MCP Proxy (OpenClaw)

```bash
# Launch with sandbox and MCP proxy
avakill launch --agent openclaw --policy strict.yaml -- \
    avakill mcp-proxy --upstream-cmd openclaw --upstream-args start
```

### MCP Proxy only (Cline)

Update your `.vscode/cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "avakill",
      "args": ["mcp-proxy", "--upstream-cmd", "python", "--upstream-args", "server.py"]
    }
  }
}
```

## Tetragon Integration

For Kubernetes deployments, generate Tetragon TracingPolicies from agent profiles:

```bash
# Generate with binary scoping and Override action
avakill enforce tetragon \
    --policy strict.yaml \
    --match-binaries /usr/bin/node,/usr/bin/npx \
    --action Override \
    -o tetragon-openclaw.yaml
```

The `matchBinaries` selector scopes enforcement to specific agent binaries, preventing false positives from other workloads. The `Override` action returns EPERM instead of killing the process, allowing the agent to handle the error gracefully.
