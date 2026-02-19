# Upgrade Guide: Adding Launch Mode to Hook-Based Setups

This guide is for existing AvaKill users who have hook-based protection and want to add OS-level sandboxing for defense-in-depth.

## Who This Is For

You already have:
- An `avakill.yaml` policy file
- Hooks installed for one or more agents (`avakill hook list` shows installed)
- The AvaKill daemon running (`avakill daemon start`)

You want to add:
- Kernel-enforced filesystem, network, and process restrictions
- Protection against agents bypassing hooks
- A second enforcement layer that works even if the agent is compromised

## What Changes

**Nothing breaks.** Your existing hooks and policies continue to work exactly as before. Launch mode adds a second layer on top:

| Layer | What it does | Status after upgrade |
|-------|-------------|---------------------|
| Hooks | Semantic tool-level decisions | Unchanged |
| Launch (new) | OS-level path/network/process restrictions | Added |

The two layers are independent. Hooks evaluate tool calls at the semantic level. Launch mode restricts what the process can do at the kernel level.

## Step-by-Step Migration

### 1. Verify Your Current Setup

```bash
# Check hooks are installed
avakill hook list

# Check policy is valid
avakill validate avakill.yaml

# Check daemon is running
avakill daemon status
```

### 2. Choose an Agent Profile

AvaKill ships with built-in containment profiles for common agents:

```bash
# List available profiles
avakill profile list

# See details for a specific profile
avakill profile show claude-code
avakill profile show aider
```

Each profile includes conservative sandbox defaults (filesystem paths, network, resource limits).

### 3. Test with Dry Run

Before launching with a real sandbox, use `--dry-run` to see what restrictions would apply:

```bash
avakill launch --agent aider --policy avakill.yaml --dry-run -- aider
```

Review the output. If paths or network endpoints are missing, you can override via the policy's `sandbox:` section.

### 4. Add Sandbox Config to Your Policy (Optional)

If the built-in profile is too restrictive, add a `sandbox:` section to your policy to customize:

```yaml
# avakill.yaml
version: "1.0"
default_action: deny

policies:
  # ... your existing rules stay the same ...

sandbox:
  allow_paths:
    read:
      - "/usr"
      - "/home/me/projects"
    write:
      - "/tmp"
      - "/home/me/projects"
    execute:
      - "/usr/bin/python3"
      - "/usr/bin/git"
  allow_network:
    connect:
      - "api.openai.com:443"
  resource_limits:
    max_memory_mb: 2048
    max_processes: 20
    timeout_seconds: 3600
```

When `--agent` is used with a policy that has a `sandbox:` section, the policy's sandbox overrides the profile's defaults.

### 5. Launch with Sandbox

```bash
# Launch with the agent profile's sandbox defaults
avakill launch --agent aider --policy avakill.yaml -- aider --model gpt-4

# Or with your own command
avakill launch --policy avakill.yaml -- python my_agent.py
```

### 6. Add MCP Proxy (Optional)

For MCP-native agents, add a third layer with the MCP proxy:

```bash
# Wrap all MCP server configs for an agent
avakill mcp-wrap --target claude-code

# Or launch with both sandbox and MCP proxy
avakill launch --agent openclaw --policy avakill.yaml -- \
    avakill mcp-proxy --upstream-cmd openclaw --upstream-args start
```

## Decision Guide

| Scenario | Recommendation |
|----------|---------------|
| Trusted agent, hook support | Hooks only |
| Trusted agent, no hook support | Launch only |
| Untrusted agent, hook support | Hooks + Launch |
| Untrusted agent, MCP-native | Launch + MCP Proxy |
| High-risk production | All three layers |
| VS Code extension (Cline, Continue) | MCP Proxy only |

## Backward Compatibility

- All existing policies work unchanged
- Hooks continue to function with or without launch mode
- The `sandbox:` section in policy YAML is optional
- `avakill init`, `avakill validate`, and all other commands are unaffected
- Agent profiles are additive -- they never modify your existing policy rules

## Further Reading

- [Defense-in-Depth Composition Guide](defense-in-depth.md) -- full risk matrix and layer diagrams
- [Process Launcher](process-launcher.md) -- sandbox backend details (Landlock, macOS, Windows)
- [Sandbox Backends](sandbox-backends.md) -- platform-specific sandbox documentation
