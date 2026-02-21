# Sandbox Backends

AvaKill's process launcher uses platform-specific sandbox backends to restrict child processes at the OS level. Each backend implements the `SandboxBackend` protocol and is auto-detected based on the current platform.

## Supported Platforms

| Platform | Backend | Mechanism | Kernel Requirement |
|----------|---------|-----------|-------------------|
| Linux | `LandlockBackend` | Landlock LSM | Linux 5.13+ (ABI 1-6) |
| macOS | `DarwinSandboxBackend` | `sandbox_init_with_parameters()` | macOS 12+ |
| Windows | `WindowsSandboxBackend` | AppContainer + Job Objects | Windows 10+ |
| Other | `NoopSandboxBackend` | None (logs warning) | Any |

## Architecture

```
ProcessLauncher
    |
    +-- get_sandbox_backend()  -->  SandboxBackend (Protocol)
    |                                   |
    |                                   +-- LandlockBackend
    |                                   +-- DarwinSandboxBackend
    |                                   +-- WindowsSandboxBackend
    |                                   +-- NoopSandboxBackend
    |
    +-- SandboxConfig (from policy.sandbox)
```

**Important:** The platform sandbox backend is only activated when a `sandbox:` section is present in the policy YAML or when using `--agent` (which loads a profile with sandbox paths). Without either, the launcher falls back to `NoopSandboxBackend` and no OS-level restrictions are applied.

### SandboxBackend Protocol

Every backend implements five methods:

- `available()` - Can this backend operate on the current system?
- `prepare_preexec(config)` - Return a preexec_fn for Unix subprocess fork
- `prepare_process_args(config)` - Return extra kwargs for subprocess.Popen
- `post_create(pid, config)` - Post-fork setup (Windows: resume suspended process)
- `describe(config)` - Dry-run report of what restrictions would be applied

## Configuration

Sandbox configuration lives in the `sandbox` section of your policy YAML:

```yaml
version: "1.0"
default_action: allow
policies:
  - name: allow-safe
    tools: ["*"]
    action: allow

sandbox:
  allow_paths:
    read:
      - /usr
      - /bin
      - /lib
      - ~/project
    write:
      - ~/project/output
      - /tmp
    execute:
      - /usr/bin/python3
      - /usr/bin/node
  allow_network:
    connect:
      - "api.anthropic.com:443"
      - "registry.npmjs.org:443"
    bind: []
  resource_limits:
    max_memory_mb: 2048
    max_open_files: 1024
    max_processes: 50
    timeout_seconds: 300
```

## Platform Details

### Linux: Landlock

Uses the Landlock LSM (Linux Security Module) to restrict filesystem access and network connections. Applied via `preexec_fn` using raw syscalls through ctypes.

**Features by ABI version:**
- ABI 1: Filesystem access control (read, write, execute, create, delete)
- ABI 2: File refer (cross-directory rename)
- ABI 3: File truncate
- ABI 4: TCP network control (connect, bind)
- ABI 5: Device ioctl
- ABI 6: IPC scoping

**How it works:**
1. `prepare_preexec()` returns a closure that calls `LandlockEnforcer.apply_to_child()`
2. The closure runs in the child process after fork, before exec
3. Only async-signal-safe operations are used (raw ctypes syscalls)
4. Restrictions are irrevocable for the child's lifetime

### macOS: sandbox_init_with_parameters

Uses Apple's `sandbox_init_with_parameters()` API via ctypes to apply a Seatbelt (SBPL) profile. This is the same mechanism used by OpenAI's Codex CLI.

**How it works:**
1. `generate_sbpl_profile()` creates a deny-default SBPL profile from `SandboxConfig`
2. The profile is passed as inline SBPL to `sandbox_init_with_parameters()` in `preexec_fn`
3. The sandbox is applied before exec, so the child process inherits all restrictions

**SBPL profile structure:**
```scheme
(version 1)
(deny default)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (subpath "/usr"))
(allow file-write* (subpath "/tmp"))
(allow process-exec (literal "/usr/bin/python3"))
```

**Note:** `sandbox_init_with_parameters()` is a private API. While stable as of macOS 15 Sequoia, monitor Apple's direction on sandbox APIs.

### Windows: AppContainer + Job Objects

Combines three security mechanisms for defense-in-depth:

1. **AppContainer** - Creates an isolated container with its own SID. By default, the container has zero filesystem access. DACL entries are added to grant access to specific directories.

2. **Job Objects** - Enforce resource limits (memory, process count) and ensure all child processes are terminated when the job is closed.

3. **Privilege Removal** - Strips dangerous token privileges (irreversible):
   - `SeRestorePrivilege` (bypass write ACLs)
   - `SeBackupPrivilege` (bypass read ACLs)
   - `SeTakeOwnershipPrivilege` (steal ownership)
   - `SeDebugPrivilege` (attach to any process)
   - `SeImpersonatePrivilege` (impersonate tokens)

**How it works:**
1. Process is created with `CREATE_SUSPENDED`
2. AppContainer profile is created, DACL entries added for allowed paths
3. Job Object is created with resource limits
4. Dangerous privileges are removed from the process token
5. Primary thread is resumed

## Usage

### CLI

```bash
# Launch with sandbox using an agent profile (provides sandbox paths)
avakill launch --agent aider --policy policy.yaml -- aider

# Launch with sandbox (policy must contain a sandbox: section)
avakill launch --policy policy-with-sandbox.yaml -- python3 agent.py

# Dry-run to preview sandbox restrictions
avakill launch --dry-run --agent openclaw --policy policy.yaml
```

### Python API

```python
from avakill.launcher.core import ProcessLauncher
from avakill.core.models import PolicyConfig

policy = PolicyConfig.from_yaml("policy.yaml")
launcher = ProcessLauncher(policy=policy)
result = launcher.launch(["python3", "agent.py"])
print(f"Exit code: {result.exit_code}")
print(f"Sandbox applied: {result.sandbox_applied}")
```

### Explicit Backend

```python
from avakill.launcher.backends.darwin_backend import DarwinSandboxBackend

launcher = ProcessLauncher(
    policy=policy,
    backend=DarwinSandboxBackend(),
)
```

## Limitations

| Platform | Limitation |
|----------|-----------|
| Linux | Landlock requires kernel 5.13+; older kernels fall back to noop |
| macOS | `sandbox_init_with_parameters()` is a private API; may change |
| macOS | SBPL profiles require careful tuning for each workload |
| Windows | AppContainer DACL manipulation may require elevated privileges |
| Windows | AppContainer profiles persist across reboots (cleanup needed) |
| All | Resource limits (rlimit) not enforced on Windows via setrlimit |
