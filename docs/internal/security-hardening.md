# Security Hardening Guide

AvaKill uses defense in depth — multiple independent layers that each catch different attack vectors. No single layer is perfect, but an agent would have to defeat all of them simultaneously to weaken its guardrails.

## The Layered Defense Model

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 6: OS Enforcement (Landlock, sandbox-exec, Tetragon)  │  ← Kernel-level restrictions
├──────────────────────────────────────────────────────────────┤
│  Layer 5: Daemon Socket Security (Unix permissions, PID)     │  ← Controls daemon access
├──────────────────────────────────────────────────────────────┤
│  Layer 4: OS Hardening (chattr/schg, SELinux, AppArmor)      │  ← Blocks kernel-level access
├──────────────────────────────────────────────────────────────┤
│  Layer 3: Audit Hooks (Python + optional C extension)        │  ← Detects runtime bypasses
├──────────────────────────────────────────────────────────────┤
│  Layer 2: Self-Protection (hardcoded rules)                  │  ← Blocks policy tampering
├──────────────────────────────────────────────────────────────┤
│  Layer 1: Policy Engine (YAML rules)                         │  ← Controls tool calls
└──────────────────────────────────────────────────────────────┘
```

| Layer | What it catches | What it can't catch |
|-------|----------------|---------------------|
| **Policy Engine** | Dangerous tool calls matching patterns | Tool calls that don't match any rule |
| **Self-Protection** | Attempts to modify the policy file, uninstall avakill, or run `avakill approve` | Low-level file access outside tool calls |
| **Audit Hooks** | Direct `open()` calls to protected files, import of ctypes/gc (C hooks) | Native code execution outside Python |
| **OS Hardening** | Filesystem modifications even from root-equivalent processes | Physical access, kernel exploits |
| **Daemon Socket Security** | Unauthorized processes connecting to the evaluation daemon | Processes running as the same user |
| **OS Enforcement** | Filesystem writes, process execution, network access at the kernel level | Kernel exploits, physical access |

## Policy Signing & Verification

Policy signing ensures your YAML file hasn't been tampered with between deployment and runtime. AvaKill supports two signing methods.

### HMAC-SHA256 (Simpler)

Good for single-machine deployments where the same process signs and verifies.

**Generate a key:**

```bash
avakill sign --generate-key
# Output:
# Generated signing key (hex): a1b2c3d4e5f6...
# Set it:
#   export AVAKILL_POLICY_KEY=a1b2c3d4e5f6...
```

**Sign your policy:**

```bash
export AVAKILL_POLICY_KEY=a1b2c3d4e5f6...
avakill sign avakill.yaml
# Creates avakill.yaml.sig alongside the policy
```

**Verify on load:**

```python
from avakill import Guard

# Reads AVAKILL_POLICY_KEY from environment automatically
guard = Guard(policy="avakill.yaml")

# Or pass explicitly
guard = Guard(policy="avakill.yaml", signing_key=bytes.fromhex("a1b2c3d4e5f6..."))
```

**Verify from CLI:**

```bash
avakill verify avakill.yaml
# → Valid HMAC-SHA256 signature: avakill.yaml
```

### Ed25519 (Stronger)

Asymmetric signing — the signing key never needs to exist on the production machine. Only the public verify key is deployed.

**Generate a keypair:**

```bash
avakill keygen
# Output:
# export AVAKILL_SIGNING_KEY=<private_hex>   # Keep secret, use in CI/deploy
# export AVAKILL_VERIFY_KEY=<public_hex>     # Deploy to production
```

**Sign (from CI or deploy machine):**

```bash
export AVAKILL_SIGNING_KEY=<private_hex>
avakill sign --ed25519 avakill.yaml
```

**Verify on load (production):**

```python
from avakill import Guard

# Reads AVAKILL_VERIFY_KEY from environment
guard = Guard(policy="avakill.yaml")
```

**Verify from CLI:**

```bash
export AVAKILL_VERIFY_KEY=<public_hex>
avakill verify avakill.yaml
# → Valid Ed25519 signature: avakill.yaml
```

### When to Use Which

| Scenario | Recommendation |
|----------|---------------|
| Local development | No signing needed |
| Single-server production | HMAC — simpler key management |
| Multi-server / CI pipeline | Ed25519 — private key stays in CI, only public key deployed |
| Compliance requirements | Ed25519 — non-repudiation (signing key never on prod) |

### Fail-Closed Behavior

When signing is enabled, AvaKill uses a fail-closed loading strategy:

1. **Signature valid** → load policy, cache as "last-known-good"
2. **Signature invalid** → fall back to last-known-good policy
3. **No last-known-good** → deny all tool calls (empty policy, `default_action: deny`)

Check the current status:

```python
guard.policy_status
# "verified"       — signature valid, loaded from file
# "hardened"       — signature valid + C-level audit hooks active
# "last-known-good" — current signature invalid, using cached policy
# "deny-all"       — no valid policy, all calls blocked
# "unsigned"       — no signing key configured
```

### Key Management Best Practices

- Store signing keys in your secrets manager (Vault, AWS Secrets Manager, GitHub Secrets)
- Rotate keys periodically — re-sign all policies after rotation
- For Ed25519, never deploy the private key to production machines
- Set `AVAKILL_POLICY_KEY` or `AVAKILL_VERIFY_KEY` in your environment, not in code
- Use `avakill check-hardening` in CI to verify signing is configured

## Self-Protection (Built-in)

Self-protection is a set of hardcoded rules that run **before** your policy rules on every `guard.evaluate()` call. They cannot be overridden by YAML configuration.

### What It Blocks

| Attack vector | Example | Self-protection response |
|---|---|---|
| Writing to the policy file | `file_write(path="avakill.yaml", ...)` | Deny — "Use .proposed.yaml for staging" |
| Deleting the policy file | `rm avakill.yaml` via shell tool | Deny |
| Uninstalling avakill | `shell(command="pip uninstall avakill")` | Deny |
| Running `avakill approve` | `shell(command="avakill approve ...")` | Deny — "Only humans may activate policies" |
| Modifying avakill source | `file_write(path=".../site-packages/avakill/...")` | Deny |

### How to Test It

```python
from avakill import Guard

guard = Guard(policy="avakill.yaml")

# These will all be denied by self-protection, regardless of your policy:
d = guard.evaluate("file_write", {"path": "avakill.yaml", "content": "..."})
assert not d.allowed
assert d.policy_name == "self-protection"

d = guard.evaluate("shell_execute", {"command": "pip uninstall avakill"})
assert not d.allowed

d = guard.evaluate("shell_execute", {"command": "avakill approve proposed.yaml"})
assert not d.allowed
```

### The Proposed Policy Workflow

Self-protection blocks direct writes to `avakill.yaml`, but agents can still *propose* policy changes:

1. Agent writes to `avakill.proposed.yaml` (allowed by self-protection)
2. Human reviews: `avakill review avakill.proposed.yaml`
3. Human activates: `avakill approve avakill.proposed.yaml`

### Disabling Self-Protection

Only for testing:

```python
guard = Guard(policy="avakill.yaml", self_protection=False)
```

Never disable in production.

## Shell Command Hardening

Shell commands are the most common attack surface for AI agents. AvaKill provides two policy conditions designed to work together:

- **`shell_safe: true`** — rejects commands containing shell metacharacters (pipes, redirects, chaining, subshells, variable expansion, dangerous builtins). Prevents injection attacks like `echo hello | sh`.
- **`command_allowlist: [...]`** — extracts the first whitespace-delimited token and matches it exactly. Prevents prefix-smuggling attacks like `env AVAKILL_POLICY=/dev/null echo bypassed`.

Always combine both conditions on shell allow rules, paired with a catch-all deny:

```yaml
- name: allow-safe-shell
  tools: ["shell_execute", "shell_*", "bash_*", "command_*"]
  action: allow
  conditions:
    shell_safe: true
    command_allowlist: [echo, ls, git, python, pip, cat, head, tail]

- name: deny-everything-else
  tools: ["*"]
  action: deny
```

This pattern was validated by adversarial red team testing (30/30 attack vectors blocked). The `command_allowlist` condition was added specifically after red teaming discovered that `args_match` substring matching could be bypassed by prefix-smuggling.

### Standalone Mode for Project-Level Hooks

For per-project hook setups without a daemon, use a wrapper script with `AVAKILL_POLICY` pointing to your project's policy file:

```bash
#!/bin/bash
export AVAKILL_POLICY="/path/to/project/avakill.yaml"
exec /path/to/avakill-hook-claude-code
```

See [Getting Started — Project-Level Hook Setup](../getting-started.md#9-project-level-hook-setup-standalone-mode) for the full walkthrough.

## C-Level Audit Hooks (Optional)

Python's `sys.addaudithook()` provides runtime monitoring, but it can be bypassed via `ctypes` or `gc` introspection. The C extension plugs these gaps.

### Install

```bash
pip install avakill[hardened]
```

This installs a compiled C extension (`_avakill_hooks`) that:

- Blocks `ctypes` imports (the primary bypass for Python audit hooks)
- Blocks `gc` module introspection of hook objects
- Registers hooks at the C level where Python code can't remove them

### What It Adds Over Python Hooks

| Capability | Python hooks | Python + C hooks |
|---|---|---|
| Detect writes to protected files | Yes | Yes |
| Block ctypes bypass | No | Yes |
| Block gc introspection bypass | No | Yes |
| Survive `sys.modules` manipulation | No | Yes |

### Verifying It's Active

```python
from avakill import Guard

guard = Guard(policy="avakill.yaml")
print(guard.policy_status)
# "hardened" if signing + C hooks are both active
# "verified" if signing is active but C hooks aren't
```

Or from the CLI:

```bash
avakill check-hardening avakill.yaml
```

### Limitations

- C hooks are a **detection** layer, not a sandbox. A sufficiently motivated attacker with native code execution can bypass them.
- The extension must be compiled for your platform (distributed as wheels for common platforms)
- Adds ~1ms to interpreter startup, zero overhead per evaluation

## OS-Level Hardening (Production)

The strongest protection layer — uses operating system features to prevent file modification.

### Immutable Flags

Make the policy file immutable at the filesystem level:

```bash
# Auto-detects platform (Linux chattr or macOS chflags)
sudo avakill harden avakill.yaml

# Linux specifically (chattr +i)
sudo avakill harden --chattr avakill.yaml

# macOS specifically (chflags schg)
sudo avakill harden --schg avakill.yaml
```

Once set, even root cannot modify the file without first removing the flag.

### Verify Hardening Status

```bash
avakill check-hardening avakill.yaml
```

Reports:
- Immutable flag status
- File permissions and ownership
- Signing configuration
- Signature validity

### SELinux Policy

Generate an SELinux type enforcement template:

```bash
avakill harden --selinux -o avakill_policy.te avakill.yaml

# Compile and install:
checkmodule -M -m -o avakill_policy.mod avakill_policy.te
semodule_package -o avakill_policy.pp -m avakill_policy.mod
semodule -i avakill_policy.pp
```

The SELinux policy restricts which processes can read/write the policy file.

### AppArmor Profile

Generate an AppArmor profile:

```bash
avakill harden --apparmor -o avakill.apparmor avakill.yaml

# Install:
cp avakill.apparmor /etc/apparmor.d/avakill
apparmor_parser -r /etc/apparmor.d/avakill
```

### Seccomp Filter

Generate a seccomp-bpf profile (for container deployments):

```bash
avakill harden --seccomp -o seccomp.json avakill.yaml
```

Use with Docker:

```bash
docker run --security-opt seccomp=seccomp.json ...
```

### Docker Deployment with Hardening

The `examples/docker-compose.hardened.yml` provides a hardened container configuration:

```yaml
services:
  avakill:
    image: avakill:latest
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - seccomp=seccomp.json
    deploy:
      resources:
        limits:
          memory: 256m
          cpus: "0.5"
```

Key hardening features:
- **Read-only filesystem** — prevents runtime modifications
- **Dropped capabilities** — minimal privileges
- **Seccomp filter** — restricts system calls
- **Resource limits** — prevents resource exhaustion

## OS-Level Enforcement (Landlock, sandbox-exec, Tetragon)

OS-level enforcement provides kernel-level restrictions that complement the policy engine. Unlike policy-based evaluation (which runs in userspace), these restrictions are enforced by the kernel and cannot be bypassed by the agent process.

### Landlock (Linux 5.13+)

Landlock is an unprivileged access-control mechanism in Linux. AvaKill translates deny rules into Landlock filesystem restrictions.

```bash
# Preview what would be restricted
avakill enforce landlock --policy avakill.yaml --dry-run

# Apply restrictions (IRREVERSIBLE for the current process)
avakill enforce landlock --policy avakill.yaml
```

**How deny rules translate to Landlock restrictions:**

| Deny Rule Tool Pattern | Landlock Access Flags Restricted |
|------------------------|----------------------------------|
| `file_write` | `WRITE_FILE`, `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM` |
| `file_delete` | `REMOVE_FILE`, `REMOVE_DIR` |
| `file_edit` | `WRITE_FILE` |
| `shell_execute` | `EXECUTE` |

**Important:** Once Landlock restrictions are applied, they cannot be removed for the lifetime of the process. Even root cannot regain restricted access. Test with `--dry-run` first.

### sandbox-exec (macOS)

On macOS, AvaKill generates Seatbelt Profile Language (SBPL) files from deny rules.

```bash
# Generate SBPL profile
avakill enforce sandbox --policy avakill.yaml --output avakill.sb

# Run your agent under the sandbox
sandbox-exec -f avakill.sb python my_agent.py
```

**How deny rules translate to SBPL operations:**

| Deny Rule Tool Pattern | SBPL Operations Denied |
|------------------------|----------------------|
| `file_write` | `file-write-data`, `file-write-create`, `file-write-unlink` |
| `file_delete` | `file-write-unlink` |
| `file_edit` | `file-write-data` |
| `shell_execute` | `process-exec` |
| `web_fetch` / `web_search` | `network-outbound` |

### Tetragon (Kubernetes)

For Kubernetes deployments, AvaKill generates Cilium Tetragon `TracingPolicy` resources with kprobes.

```bash
# Generate TracingPolicy
avakill enforce tetragon --policy avakill.yaml --output tetragon-policy.yaml

# Deploy to your cluster
kubectl apply -f tetragon-policy.yaml
```

Tetragon monitors kernel syscalls and sends `Sigkill` to processes that violate deny rules. This provides enforcement at the container level without modifying the application.

## Daemon Socket Security

The AvaKill daemon communicates over a Unix domain socket. Socket security is important because any process that can connect to the socket can request evaluations.

### Socket Permissions

The socket is created at `~/.avakill/avakill.sock` by default (or the path in `AVAKILL_SOCKET`). It inherits the user's umask permissions.

For production, restrict socket access:

```bash
# Restrict to owner only
chmod 700 ~/.avakill/
```

### PID File

The daemon writes its PID to `~/.avakill/avakill.pid`. This is used by:
- `avakill daemon status` to check if the daemon is running
- `avakill daemon stop` to send SIGTERM
- SIGHUP reload: `kill -HUP $(cat ~/.avakill/avakill.pid)`

### Signal Handling

| Signal | Action |
|--------|--------|
| `SIGHUP` | Reload the policy file from disk without restarting |
| `SIGTERM` | Graceful shutdown (close connections, clean up socket and PID files) |
| `SIGINT` | Graceful shutdown |

### Stale Socket Cleanup

If the daemon crashes without cleaning up, the socket file may remain. The daemon detects stale sockets on startup and removes them if no process is listening.

## End-to-End: Hardened Production Setup

Here's the complete workflow for a production deployment with maximum hardening:

### 1. Generate Keys (CI machine)

```bash
avakill keygen
# Save AVAKILL_SIGNING_KEY in your secrets manager
# Save AVAKILL_VERIFY_KEY for production deployment
```

### 2. Sign the Policy (CI pipeline)

```bash
export AVAKILL_SIGNING_KEY=<from-secrets-manager>
avakill validate avakill.yaml
avakill sign --ed25519 avakill.yaml
# Deploy avakill.yaml + avakill.yaml.sig together
```

### 3. Deploy with Verification (production)

```bash
export AVAKILL_VERIFY_KEY=<public-key-hex>
pip install avakill[hardened]
```

```python
from avakill import Guard

guard = Guard(policy="avakill.yaml")
assert guard.policy_status == "hardened"  # Signed + C hooks active
```

### 4. Apply OS Hardening

```bash
# Set immutable flag
sudo avakill harden avakill.yaml

# Verify everything
avakill check-hardening avakill.yaml
```

### 5. Verify in CI

Add to your CI pipeline:

```bash
avakill validate avakill.yaml
avakill verify avakill.yaml
avakill check-hardening avakill.yaml
```

---

## Further Reading

- **[Deployment Guide](deployment.md)** — dev → staging → production patterns
- **[Policy Reference](../policy-reference.md)** — full YAML schema
- **[CLI Reference](../cli-reference.md)** — all security-related commands
- **[Troubleshooting](troubleshooting.md)** — common security issues
