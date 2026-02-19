# Process Launcher

The process launcher (`avakill launch`) spawns an agent process inside an OS-level sandbox. On Linux, this means applying Landlock filesystem and network restrictions to the child process **before** it starts — the child inherits the sandbox and cannot escape it.

## When to Use

| Approach | Use When |
|----------|----------|
| `avakill launch` | You control how the agent starts and want OS-level containment |
| Hook adapters | The agent supports hook/callback integration (Claude Code, Cursor) |
| `@protect` decorator | You're writing Python code that calls tools directly |

The launcher is the strongest containment option — it restricts the process at the kernel level, regardless of whether the agent cooperates.

## CLI Reference

```bash
avakill launch [OPTIONS] -- COMMAND [ARGS...]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--policy PATH` | `avakill.yaml` | Path to policy YAML file |
| `--pty / --no-pty` | `--no-pty` | Allocate PTY for interactive agents |
| `--dry-run` | off | Show sandbox restrictions without launching |
| `--timeout N` | none | Kill child after N seconds |

### Exit Codes

- **0**: Child exited successfully
- **1-125**: Child's exit code (propagated)
- **126**: Sandbox setup failed
- **127**: Command not found

### Examples

```bash
# Launch with default policy
avakill launch -- python my_agent.py

# Launch with a strict policy
avakill launch --policy strict.yaml -- openclaw start

# Dry-run to inspect sandbox
avakill launch --dry-run -- aider --model gpt-4

# Interactive agent with PTY
avakill launch --pty -- python -i agent_repl.py

# With timeout
avakill launch --timeout 3600 -- long_running_agent
```

## Sandbox YAML Schema

Add a `sandbox` section to your policy YAML:

```yaml
version: "1.0"
default_action: deny
policies:
  - name: deny-writes
    tools: ["file_write"]
    action: deny

sandbox:
  allow_paths:
    read: ["/usr", "/bin", "/lib", "~/.config/myagent"]
    write: ["/tmp", "~/project"]
    execute: ["/usr/bin/python3", "/usr/bin/node"]

  allow_network:
    connect: ["api.anthropic.com:443", "api.openai.com:443"]
    bind: []

  resource_limits:
    max_memory_mb: 512
    max_open_files: 1024
    max_processes: 50
    timeout_seconds: 3600

  inherit_env: true
  inject_hooks: true
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_paths.read` | `list[str]` | `[]` | Paths the child can read |
| `allow_paths.write` | `list[str]` | `[]` | Paths the child can write |
| `allow_paths.execute` | `list[str]` | `[]` | Binaries the child can run |
| `allow_network.connect` | `list[str]` | `[]` | Outbound TCP targets (`host:port`) |
| `allow_network.bind` | `list[str]` | `[]` | TCP bind targets (`host:port`) |
| `resource_limits.max_memory_mb` | `int?` | `null` | Memory limit in MB |
| `resource_limits.max_open_files` | `int?` | `null` | Max open file descriptors |
| `resource_limits.max_processes` | `int?` | `null` | Max child processes |
| `resource_limits.timeout_seconds` | `int?` | `null` | Kill child after N seconds |
| `inherit_env` | `bool` | `true` | Inherit parent environment |
| `inject_hooks` | `bool` | `true` | Inject AvaKill hook env vars |

Paths support `~` for home directory expansion.

## Per-Agent Examples

### OpenClaw

```yaml
sandbox:
  allow_paths:
    read: ["/usr", "/bin", "/lib", "~/.config/openclaw"]
    write: ["~/projects/current", "/tmp"]
    execute: ["/usr/bin/python3"]
  allow_network:
    connect: ["api.anthropic.com:443"]
  resource_limits:
    max_memory_mb: 1024
    timeout_seconds: 7200
```

```bash
avakill launch --policy openclaw.yaml -- openclaw start
```

### Aider

```yaml
sandbox:
  allow_paths:
    read: ["/usr", "/bin", "/lib", "~/project"]
    write: ["~/project", "/tmp"]
    execute: ["/usr/bin/python3", "/usr/bin/git"]
  allow_network:
    connect: ["api.openai.com:443", "api.anthropic.com:443"]
```

```bash
avakill launch --pty --policy aider.yaml -- aider --model gpt-4
```

### Cline (VS Code Extension Agent)

```yaml
sandbox:
  allow_paths:
    read: ["/usr", "/bin", "/lib", "~/workspace"]
    write: ["~/workspace", "/tmp"]
    execute: ["/usr/bin/node", "/usr/bin/npx"]
  allow_network:
    connect: ["api.anthropic.com:443"]
  resource_limits:
    max_memory_mb: 2048
```

## Security Model

The launcher applies defense in depth:

| Layer | What It Stops | Mechanism |
|-------|--------------|-----------|
| **Landlock FS** | Unauthorized file read/write/delete | Kernel-level path restrictions |
| **Landlock Net** | Unauthorized network connections (ABI 4+) | Kernel-level port restrictions |
| **Resource limits** | Memory exhaustion, fork bombs | `setrlimit()` |
| **Process isolation** | Signal leakage, process group escape | `setsid()`, signal forwarding |
| **Environment** | Policy/socket discovery | `AVAKILL_POLICY`, `AVAKILL_SOCKET` injection |

The sandbox is applied **before** the target command runs (in `preexec_fn`), so even a malicious agent cannot escape it.

## Limitations

- **Linux only**: Landlock requires Linux 5.13+. On macOS/Windows, the launcher warns and runs without OS-level sandbox (Phase B will add platform-specific support).
- **Network rules require ABI 4+**: Landlock network filtering requires Linux 6.2+ (ABI 4). On older kernels, network rules are silently skipped.
- **PTY mode is opt-in**: Default is pipe-based I/O. Use `--pty` only for interactive agents that need terminal access.
- **No GPU isolation**: The launcher does not restrict GPU/device access (future work with cgroups).
- **Python startup cost**: The launcher adds ~30ms of Python startup time. This is acceptable for a one-time session launcher.
