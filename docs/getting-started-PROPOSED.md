## 1. Set Up Your Policy

### Interactive setup with `avakill setup`

The recommended way to get started:

```bash
avakill setup
```

This walks you through an interactive flow:

1. **Detect agents** -- scans your machine for AI agents across three protection paths
2. **Create policy** -- builds an `avakill.yaml` from a rule catalog you customize interactively
3. **Install hooks** -- wires AvaKill into detected hook agents as a pre-tool-use check
4. **Wrap MCP servers** -- intercepts MCP server traffic through AvaKill's proxy
5. **OS Sandbox guidance** -- shows launch commands for sandbox-capable agents
6. **Enable tracking** -- optionally starts a background service for logging and diagnostics
7. **Verify & summarize** -- validates the generated policy and shows what was configured

#### Step 1: Agent detection

Setup scans for agents across all three enforcement paths:

```
Scanning your machine...

  Agents found:

    Hooks (native agent integration):
      ✓ Claude Code       ~/.claude/
      ✓ Gemini CLI        ~/.gemini/
      · Cursor            not detected
      · Windsurf          not detected
      ✓ OpenAI Codex      ~/.codex/

    MCP Proxy (wrap MCP servers):
      ✓ Claude Desktop    ~/Library/Application Support/Claude/
      · Cline             not detected
      · Continue.dev      not detected

    OS Sandbox (avakill launch):
      ✓ OpenClaw          ~/.openclaw/
      · Aider             not detected
      · SWE-Agent         not detected
```

Each group maps to a different enforcement path. The remaining steps configure each path for the agents that were detected.

#### Step 2: Policy creation

Setup starts with two **essential rules** that are always included:

- **Catastrophic shell commands** -- blocks `rm -rf /`, `mkfs`, `dd if=`, `> /dev/`, fork bombs
- **Catastrophic SQL** -- blocks `DROP DATABASE`/`DROP SCHEMA` via shell and database tools

Then it presents the **rule catalog** -- 81 optional rules across 14 categories:

| Category | Rules | Examples |
|----------|-------|---------|
| Shell Safety | 12 | Dangerous commands, privilege escalation, obfuscation, pipe-to-shell |
| Database Safety | 3 | Destructive SQL, unqualified DML, permission changes |
| Filesystem Protection | 14 | Path-aware deletion, system dir writes, symlink escapes, persistence |
| Tool Safety | 1 | Block `delete_*`, `remove_*`, `destroy_*` tool patterns |
| Secrets & Access | 9 | SSH keys, cloud credentials, secret detection, PATH poisoning |
| Rate Limits | 2 | Web search throttling, agent spawning limits |
| Version Control | 3 | Force push, branch deletion, credential commits |
| Supply Chain | 2 | Registry manipulation, postinstall scripts |
| Network & Exfiltration | 8 | Encode-transmit chains, DNS exfil, SSH, firewall changes |
| Cloud & Infrastructure | 6 | Resource deletion, Docker, container escape, backup deletion |
| AI Agent Safety | 5 | MCP poisoning, self-modification, tool rate limits |
| OS Hardening | 16 | macOS SIP/TCC/Gatekeeper, Linux kernel/MAC, Windows Defender/UAC/LSASS |

63 of these are pre-selected by default. You toggle rules on and off by number:

```
What else should AvaKill block?
Type numbers to toggle, 'a' for all, Enter to confirm.

Shell Safety  Dangerous commands, privilege escalation, obfuscation
──────────────────────────────────────────────────
   1. ✓ Dangerous shell commands
      Block rm -rf, sudo, chmod 777
   2. [ ] Package install approval
      Require approval for pip install, npm install -g, brew install
   3. [ ] Shell command allowlist
      Only allow approved shell commands (echo, ls, git, python, ...)
   ...
```

After rule selection, you choose a **default action** for tool calls that don't match any rule:

```
Default action (when no rule matches):

  1. allow  Log and allow unmatched calls (recommended)
  2. deny   Block anything not explicitly allowed (stricter)
```

Setup then offers to **scan your project** for sensitive files (`.env`, database files, keys, credentials) and adds protective deny rules for anything it finds.

If you selected any configurable rate limit rules, setup prompts you to customize the thresholds:

```
Tool call rate limit — currently 500 calls/60m
Customize max calls? (500):
```

At the end you'll see something like:

```
✓ Created avakill.yaml (67 rules, default: deny)
```

#### Step 3: Hook installation

For each detected hook agent, setup shows the exact config file it will modify:

```
Install hooks for your detected agents?

  This adds AvaKill as a pre-tool-use check. Your agents will work
  normally — AvaKill only intervenes when a tool call matches a
  block rule.

  • Claude Code     → ~/.claude/settings.json
  • Gemini CLI      → .gemini/settings.json
  • OpenAI Codex    → ~/.codex/config.toml

Install? [y/n] (y):
```

Each hook is smoke-tested after installation to verify `avakill` is on your PATH. If you skip this step, you can install later with `avakill hook install --agent all`.

#### Step 4: MCP wrapping

If MCP-capable agents were detected (Claude Desktop, Cline, Continue.dev), setup offers to wrap their MCP servers:

```
Wrap MCP servers for your detected agents?

  This intercepts all MCP server traffic through AvaKill's proxy.
  Your MCP servers work normally — AvaKill scans requests and
  responses for policy violations.

  ✓ Claude Desktop    already wrapped
```

If servers are already wrapped, setup reports their status. Unwrapped servers are listed with a count of how many will be wrapped. You can skip and wrap later with `avakill mcp-wrap --agent all`.

#### Step 5: OS Sandbox guidance

If sandbox-capable agents were detected (OpenClaw, Aider, SWE-Agent), setup shows how to launch them:

```
OS Sandbox agents detected

  These agents are protected by running them through AvaKill's
  OS-level sandbox. No config changes needed — just launch with:

  • OpenClaw        avakill launch --agent openclaw
```

No configuration is needed -- OS sandboxing is applied at launch time.

#### Step 6: Activity tracking

Setup offers to start a lightweight background service that powers diagnostics and monitoring:

```
Enable activity tracking?

  This runs a lightweight background service that powers:
    • avakill fix        See why something was blocked
    • avakill logs       View agent activity history
    • avakill dashboard  Live monitoring

  Without it, hooks still protect you — you just won't have
  history or diagnostics.

Enable? [y/n] (y):
```

Activity tracking is optional. Hooks, MCP wrapping, and OS sandboxing all enforce your policy regardless. You can enable it later with `avakill tracking on`.

#### Step 7: Summary

Setup validates the policy and prints a summary of everything that was configured:

```
✓ Policy valid  (67 rules, default: deny)

─────────────────────────────────────────────────────

Setup complete. Your agents are now protected.

  Policy:     avakill.yaml (67 rules)
  Tracking:   off
  Hooks:      Claude Code, Gemini CLI, OpenAI Codex
  MCP:        Claude Desktop
  Sandbox:    OpenClaw (protect with: avakill launch --agent openclaw)

If something gets blocked:
  Run  avakill fix       to see why and how to fix it
  Edit avakill.yaml   to change your rules

Enable activity tracking anytime: avakill tracking on

─────────────────────────────────────────────────────
```

### Validate your policy

Whether generated by `avakill setup` or written by hand:

```bash
$ avakill validate avakill.yaml

Policy Rules: 67 rules (block-catastrophic-shell, block-catastrophic-sql-shell, ...)
Version: 1.0 | Default action: deny | Total rules: 67

Policy is valid.
```

### LLM-assisted policy creation

Instead of writing YAML manually, you can use any LLM to generate a policy:

```bash
# Generate a self-contained prompt and paste it into any LLM
avakill schema --format=prompt

# Include your tool names for a tailored policy
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_read" --use-case="data pipeline"
```

The prompt includes the full JSON Schema, evaluation rules, and examples. Paste it into any LLM, describe your agent, then validate with `avakill validate generated-policy.yaml`. See [`llm-policy-prompt.md`](internal/llm-policy-prompt.md) for a paste-ready version.
