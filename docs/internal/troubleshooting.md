# Troubleshooting

## Policy Issues

### "No matching rule" — all calls denied (or allowed) unexpectedly

AvaKill uses **first-match-wins** evaluation. Rules are checked top-to-bottom, and the first rule whose tool pattern and conditions match is applied.

**Common cause:** A broad rule is placed before a specific one.

```yaml
# WRONG — the allow rule matches first, deny never fires
policies:
  - name: "allow-sql"
    tools: ["execute_sql"]
    action: allow

  - name: "block-destructive-sql"
    tools: ["execute_sql"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE"]
```

```yaml
# CORRECT — specific deny rule first, then broader allow
policies:
  - name: "block-destructive-sql"
    tools: ["execute_sql"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE"]

  - name: "allow-sql"
    tools: ["execute_sql"]
    action: allow
```

**Debugging:** Use `avakill validate` to see the rule order, then check which rule matches first.

### Rate limit hitting unexpectedly

Rate limits use a **sliding window**. If you set `max_calls: 10, window: "60s"`, the 11th call within any 60-second sliding window is blocked.

**Common causes:**

- Window is shorter than expected (e.g. `60s` is 1 minute, not 1 hour — use `1h`)
- Multiple tools match the same rate-limited rule (glob patterns)
- Rate limits reset on restart (in-memory by default). Use `SQLiteBackend` for persistence.

**Check your window format:** Must be `<number>[s|m|h]` — `60s`, `5m`, `1h`.

### Glob pattern not matching

AvaKill uses Python's `fnmatch` for pattern matching:

| Pattern | Matches | Does NOT match |
|---------|---------|---------------|
| `*` | Everything | — |
| `delete_*` | `delete_user`, `delete_file` | `user_delete` |
| `*_read` | `file_read`, `db_read` | `read_file` |
| `*sql*` | `execute_sql`, `sql_query` | — |
| `database_*` | `database_query`, `database_delete` | `db_query` |

Pattern matching is **case-sensitive**. `Delete_User` will not match `delete_*`.

### Environment variable not substituting

Environment variables use `${VAR_NAME}` syntax in YAML:

```yaml
rate_limit:
  max_calls: ${API_RATE_LIMIT}
  window: "60s"
```

**Common causes:**

- Variable not set in the environment before the policy is loaded
- Using `$VAR_NAME` instead of `${VAR_NAME}` (braces are required)
- Variable contains non-numeric value for a numeric field

## Integration Issues

### OpenAI: tool_calls still executing after denied

The `GuardedOpenAIClient` wrapper filters denied tool calls from the **response**. If you're manually iterating over `tool_calls` and executing them, you need to check decisions yourself:

```python
# If using the wrapper — denied calls are already removed:
client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")
response = client.chat.completions.create(...)
# response.choices[0].message.tool_calls only contains allowed calls

# If manual — check each call:
for tc in response.choices[0].message.tool_calls:
    decision = guard.evaluate(tc.function.name, json.loads(tc.function.arguments))
    if not decision.allowed:
        continue
    execute_tool(tc.function.name, tc.function.arguments)
```

### Anthropic: tool_use blocks not filtered

Same pattern — use `GuardedAnthropicClient` for automatic filtering, or check manually:

```python
for block in response.content:
    if block.type == "tool_use":
        decision = guard.evaluate(block.name, block.input)
        if not decision.allowed:
            continue
        execute_tool(block.name, block.input)
```

### LangChain: PolicyViolation not caught

The `AvaKillCallbackHandler` raises `PolicyViolation` in `on_tool_start`. If your chain doesn't handle this exception, it propagates to the caller.

```python
from avakill import PolicyViolation

try:
    agent.invoke({"input": "..."}, config={"callbacks": [handler]})
except PolicyViolation as e:
    print(f"Blocked: {e.tool_name} — {e.decision.reason}")
```

### MCP proxy: upstream not starting

**Common causes:**

- Wrong `--upstream-cmd` path (use absolute paths or ensure it's on `$PATH`)
- Missing `--upstream-args` (space-separated, not comma-separated)
- Upstream server crashes on startup (test it standalone first)

```bash
# Test upstream standalone first:
python server.py

# Then wrap with proxy:
avakill mcp-proxy --upstream-cmd python --upstream-args "server.py" --policy avakill.yaml
```

## CLI Issues

### Dashboard shows no events

**Causes:**

1. **No logger configured** — the Guard must have a logger to write to the database:
   ```python
   from avakill.logging.sqlite_logger import SQLiteLogger
   logger = SQLiteLogger("avakill_audit.db")
   guard = Guard(policy="avakill.yaml", logger=logger)
   ```

2. **Wrong database path** — the dashboard must point to the same database:
   ```bash
   avakill dashboard --db avakill_audit.db
   ```

3. **No events yet** — the agent hasn't made any tool calls since the logger was configured.

### `avakill logs` shows empty results

- **Wrong `--db` path:** Check that the path matches your `SQLiteLogger` path.
- **Filter too restrictive:** Try without filters first: `avakill logs`
- **Events not flushed:** SQLiteLogger uses batched writes. Events flush every 100ms or 50 events. Force a flush by closing the logger.

### `avakill validate` passes but runtime fails

`validate` checks YAML syntax and schema. Runtime failures can be caused by:

- **Environment variables** not set at runtime (`${VAR_NAME}` resolves to empty)
- **Rate limit backend** not available (SQLite path not writable)
- **Signing key mismatch** — validate doesn't check signatures unless `AVAKILL_POLICY_KEY` is set

## Security Issues

### `policy_status` showing "unsigned" in production

The Guard only verifies signatures when a signing/verify key is available:

```python
# Check if key is set:
import os
print(os.environ.get("AVAKILL_POLICY_KEY"))    # For HMAC
print(os.environ.get("AVAKILL_VERIFY_KEY"))     # For Ed25519

# Pass explicitly if env var isn't working:
guard = Guard(
    policy="avakill.yaml",
    signing_key=bytes.fromhex("your-key-hex"),
)
print(guard.policy_status)  # Should be "verified"
```

### C hooks not loading

```python
from avakill.core.audit_hooks import c_hooks_available
print(c_hooks_available())  # False if not installed
```

**Fix:** Install the hardened extra:

```bash
pip install avakill[hardened]
```

The C extension must be compiled for your platform. Check that the `.so` (Linux/macOS) or `.pyd` (Windows) file exists:

```bash
python -c "import avakill._avakill_hooks; print('OK')"
```

### Self-protection blocking legitimate changes

Self-protection blocks tool calls that target `avakill.yaml` or `avakill.yml`. This includes:

- Any tool with "write", "delete", "modify" etc. in its name that references the policy file
- Shell commands that `rm`, `mv`, or redirect to the policy file

**Workarounds:**

- Use the proposed policy workflow: write to `avakill.proposed.yaml`, then a human runs `avakill approve`
- For testing, disable self-protection: `Guard(self_protection=False)`
- Self-protection does NOT block reads — tools can always read the policy file

## Performance

### Evaluation taking >1ms

Typical evaluation is <1ms. If you're seeing higher:

- **Large policy file** — more rules = more matching. Keep policies under 50 rules for optimal performance.
- **Many rate-limited rules** — each rate-limited rule maintains timestamps. With persistent backend (SQLite), this adds I/O.
- **OTel/Prometheus overhead** — telemetry is fault-isolated but adds some overhead. Check if the telemetry SDK is misconfigured.

**Measure evaluation time:**

```python
decision = guard.evaluate(tool="test", args={})
print(f"Latency: {decision.latency_ms:.3f}ms")
```

**Monitor with Prometheus:**

```
histogram_quantile(0.99, rate(avakill_evaluation_duration_seconds_bucket[5m]))
```

---

## Daemon Issues

### Daemon not starting

**Common causes:**

- **Socket already in use** — another daemon instance may be running, or a stale socket file exists:
  ```bash
  avakill daemon status
  # If not running but socket exists:
  rm ~/.avakill/avakill.sock
  avakill daemon start
  ```

- **Permission denied on socket directory** — ensure `~/.avakill/` exists and is writable:
  ```bash
  mkdir -p ~/.avakill
  ```

- **Policy file not found** — use an absolute path:
  ```bash
  avakill daemon start --policy /absolute/path/to/avakill.yaml
  ```

### Connection refused

The daemon is not running or the socket path doesn't match:

```bash
# Check status
avakill daemon status

# Verify socket path matches
echo $AVAKILL_SOCKET  # Should match daemon's --socket flag
```

### SIGHUP reload not working

```bash
# Verify the PID file exists and matches a running process
cat ~/.avakill/avakill.pid
kill -0 $(cat ~/.avakill/avakill.pid)  # Should succeed silently

# Send reload signal
kill -HUP $(cat ~/.avakill/avakill.pid)
```

If the policy file has syntax errors, the reload will fail silently and the old policy remains active. Validate first:

```bash
avakill validate avakill.yaml
```

### Stale PID file

If the daemon crashes without cleanup, the PID file may reference a dead process:

```bash
# Check if PID is actually running
kill -0 $(cat ~/.avakill/avakill.pid) 2>/dev/null || echo "Stale PID"

# Clean up and restart
rm ~/.avakill/avakill.pid ~/.avakill/avakill.sock
avakill daemon start
```

---

## Hook Issues

### Hook not triggering

**Common causes:**

1. **Hook not installed** — verify with `avakill hook list`
2. **Agent not restarted** — restart the agent after installing hooks
3. **Daemon not running** — hooks need the daemon (or `AVAKILL_POLICY` env var for standalone mode):
   ```bash
   avakill daemon status
   # If not running:
   avakill daemon start --policy avakill.yaml
   ```

### Wrong tool names in policy

Hooks use canonical tool names, not agent-native names. If your policy uses agent-native names, they won't match:

```yaml
# WRONG — uses Claude Code's native name
- name: "block-shell"
  tools: ["Bash"]
  action: deny

# CORRECT — uses canonical name
- name: "block-shell"
  tools: ["shell_execute"]
  action: deny
```

See the [tool normalization table](framework-integrations.md#tool-normalization) for the full mapping.

### Agent restart needed

After installing or uninstalling hooks, the agent must be restarted for changes to take effect. This applies to all agents: Claude Code, Gemini CLI, Cursor, and Windsurf.

### Standalone fallback not working

If the daemon is unreachable and the hook should fall back to standalone mode:

```bash
# Set the policy path for standalone mode
export AVAKILL_POLICY=/path/to/avakill.yaml
```

Without this environment variable, hooks that can't reach the daemon will deny all calls (fail-closed).

---

## Enforcement Issues

### Landlock unavailable

Landlock requires Linux 5.13+ with Landlock support enabled in the kernel:

```bash
avakill enforce landlock --policy avakill.yaml --dry-run
# If unavailable: "Landlock is not available on this system"
```

**Fix:** Upgrade to Linux 5.13+ or check that `CONFIG_SECURITY_LANDLOCK=y` in your kernel config.

### sandbox-exec macOS only

`avakill enforce sandbox` only works on macOS:

```bash
avakill enforce sandbox --policy avakill.yaml --output avakill.sb
# On non-macOS: "sandbox-exec is only available on macOS"
```

### Tetragon kubectl issues

The generated TracingPolicy requires Cilium Tetragon to be installed in your Kubernetes cluster:

```bash
# Check if Tetragon is installed
kubectl get pods -n kube-system | grep tetragon

# Apply the policy
kubectl apply -f tetragon-policy.yaml

# Check policy status
kubectl get tracingpolicies
```

If `kubectl apply` fails, verify that the Tetragon CRDs are installed.

---

## Compliance Issues

### All controls failing

If every compliance control reports "fail", check these common causes:

1. **Policy uses `default_action: allow`** — most frameworks require deny-by-default
2. **No audit logging configured** — several controls check for logging:
   ```python
   from avakill.logging.sqlite_logger import SQLiteLogger
   logger = SQLiteLogger("audit.db")
   guard = Guard(policy="avakill.yaml", logger=logger)
   ```
3. **No rate limiting rules** — add `rate_limit` to at least some rules
4. **No policy signing** — run `avakill keygen` and `avakill sign`

### Approval database not found

The `avakill approvals` commands use `~/.avakill/approvals.db` by default:

```bash
# Use a custom path
avakill approvals list --db /path/to/approvals.db
```

The database is created automatically on first use. If it doesn't exist, ensure the directory is writable.

---

## Still Stuck?

- Check the [Policy Reference](../policy-reference.md) for YAML syntax details
- Use `avakill validate` to catch schema errors
- Use `avakill logs` to see what decisions are being made
- Use `avakill dashboard` to monitor in real-time
- Open an issue at [github.com/log-bell/avakill/issues](https://github.com/log-bell/avakill/issues)
