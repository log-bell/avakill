# Policy Reference

This is the complete reference for AvaKill policy files. Policies are YAML files that define which tool calls your agent is allowed to make.

## File Format

Policies are written in YAML. JSON support is planned for a future release.

AvaKill auto-detects `avakill.yaml` or `avakill.yml` in the current working directory. You can also pass an explicit path:

```python
guard = Guard(policy="policies/production.yaml")
```

Or load from a dict:

```python
guard = Guard(policy={
    "version": "1.0",
    "default_action": "deny",
    "policies": [
        {"name": "allow-reads", "tools": ["*_read"], "action": "allow"}
    ]
})
```

## Top-Level Fields

```yaml
version: "1.0"
default_action: deny
policies: [...]
notifications: {}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | string | No | `"1.0"` | Schema version. Accepts `"1"` or `"1.0"` (both normalize to `"1.0"`). |
| `default_action` | string | No | `"deny"` | Action when no rule matches. Must be `"allow"` or `"deny"`. |
| `policies` | list | Yes | — | Ordered list of policy rules, evaluated top-to-bottom. |
| `notifications` | object | No | `{}` | Notification configuration (reserved for future use). |
| `sandbox` | object | No | `null` | OS-level sandbox configuration (future release). See [Sandbox Configuration](#sandbox-configuration). |

## Policy Rule Fields

Each entry in the `policies` list is a rule object:

```yaml
policies:
  - name: block-destructive-sql
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE"]
    rate_limit:
      max_calls: 10
      window: "1m"
    message: "Destructive SQL is blocked"
    log: true
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | — | Human-readable name. Appears in decisions and audit logs. |
| `tools` | list[string] | Yes | — | Tool-name patterns this rule applies to. Must have at least one entry. |
| `action` | string | Yes | — | One of `"allow"`, `"deny"`, or `"require_approval"`. |
| `enforcement` | string | No | `"hard"` | Enforcement level: `"hard"`, `"soft"`, or `"advisory"`. See [Enforcement Levels](#enforcement-levels). |
| `conditions` | object | No | `null` | Argument-matching conditions (see [Conditions](#conditions)). |
| `rate_limit` | object | No | `null` | Rate limiting configuration (see [Rate Limiting](#rate-limiting)). |
| `message` | string | No | `null` | Custom message included in the decision's `reason` field. |
| `log` | bool | No | `true` | Whether to log matches against this rule. Set to `false` for noisy rules. |

### Actions

| Action | `decision.allowed` | Behavior |
|--------|-------------------|----------|
| `allow` | `true` | Tool call proceeds normally. |
| `deny` | `false` | Tool call is blocked. `PolicyViolation` raised (or `decision.allowed` is `false`). |
| `require_approval` | `false` | Tool call is flagged for human review. Treated as denied until approved. |

### Enforcement Levels

Each rule can specify an `enforcement` level that controls how strictly the rule is applied:

| Level | Behavior |
|-------|----------|
| `hard` | Decision is final. Cannot be overridden by lower-level policies. **(default)** |
| `soft` | Decision is applied but can be overridden by project or local policies. |
| `advisory` | Decision is logged but not enforced. Useful for monitoring before enforcing. |

```yaml
policies:
  - name: "block-destructive-sql"
    tools: ["execute_sql"]
    action: deny
    enforcement: hard
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE"]

  - name: "warn-large-queries"
    tools: ["execute_sql"]
    action: deny
    enforcement: advisory
    message: "Large query detected (advisory only — not enforced)"
```

Advisory rules always **allow** the tool call regardless of the rule's `action`. The returned decision has `allowed=True` with the reason prefixed `[advisory]`. This generates an audit event you can monitor without blocking anything. Use advisory rules to test new deny rules before enforcing them.

## Tool Matching Patterns

The `tools` field accepts a list of patterns. A rule matches if the tool name matches **any** pattern in the list.

### Pattern types

| Pattern | Matches | Example |
|---------|---------|---------|
| Exact | Tool name is identical | `"execute_sql"` matches only `execute_sql` |
| Glob prefix | Tools starting with a prefix | `"database_*"` matches `database_query`, `database_execute` |
| Glob suffix | Tools ending with a suffix | `"*_read"` matches `file_read`, `config_read` |
| Glob infix | Tools containing a substring | `"*sql*"` matches `execute_sql_query`, `sql_run` |
| Wildcard | Everything | `"*"` or `"all"` matches any tool name |

Glob matching uses Python's `fnmatch`, so `*` matches any sequence of characters and `?` matches any single character.

```yaml
# Match tools by prefix
tools: ["database_*"]

# Match tools by suffix
tools: ["*_read", "*_get"]

# Match exact names and globs together
tools: ["execute_sql", "db_*", "*_query"]

# Match everything
tools: ["all"]  # or ["*"]
```

### Ordering matters

Rules are evaluated top-to-bottom. **The first matching rule wins.** Place specific rules before general ones:

```yaml
policies:
  # Specific: block DROP queries in SQL tools
  - name: block-drop
    tools: ["execute_sql"]
    action: deny
    conditions:
      args_match:
        query: ["DROP"]

  # General: allow all other SQL queries
  - name: allow-sql
    tools: ["execute_sql"]
    action: allow

  # Catch-all: deny everything else
  # (Or rely on default_action: deny)
```

If you put the general `allow-sql` rule first, it would match before `block-drop` ever gets checked.

## Tool Normalization

Each AI coding agent uses its own naming convention for tools. AvaKill provides a canonical namespace so you can write policies once and apply them uniformly across agents.

### Canonical tool names

| Canonical Name | Description |
|----------------|-------------|
| `shell_execute` | Run a shell/terminal command |
| `file_read` | Read a file |
| `file_write` | Write/create a file |
| `file_edit` | Edit an existing file |
| `file_search` | Search for files by name/pattern |
| `file_list` | List directory contents |
| `content_search` | Search file contents (grep) |
| `web_fetch` | Fetch a URL |
| `web_search` | Web search |
| `agent_spawn` | Spawn a sub-agent |

### Agent-native mappings

These are the built-in mappings from each agent's native tool names to canonical names:

| Agent | Native Name | Canonical Name |
|-------|-------------|----------------|
| `claude-code` | `Bash` | `shell_execute` |
| `claude-code` | `Read` | `file_read` |
| `claude-code` | `Write` | `file_write` |
| `claude-code` | `Edit`, `MultiEdit` | `file_edit` |
| `claude-code` | `Glob` | `file_search` |
| `claude-code` | `Grep` | `content_search` |
| `claude-code` | `LS` | `file_list` |
| `claude-code` | `WebFetch` | `web_fetch` |
| `claude-code` | `WebSearch` | `web_search` |
| `claude-code` | `Task` | `agent_spawn` |
| `gemini-cli` | `run_shell_command` | `shell_execute` |
| `gemini-cli` | `read_file` | `file_read` |
| `gemini-cli` | `write_file` | `file_write` |
| `gemini-cli` | `edit_file` | `file_edit` |
| `cursor` | `shell_command` | `shell_execute` |
| `cursor` | `read_file` | `file_read` |
| `windsurf` | `run_command` | `shell_execute` |
| `windsurf` | `write_code` | `file_write` |
| `windsurf` | `read_code` | `file_read` |
| `openai-codex` | `shell`, `shell_command`, `local_shell`, `exec_command` | `shell_execute` |
| `openai-codex` | `apply_patch` | `file_write` |
| `openai-codex` | `read_file` | `file_read` |
| `openai-codex` | `list_dir` | `file_list` |
| `openai-codex` | `grep_files` | `content_search` |

MCP tools (prefixed with `mcp__` or `mcp:`) pass through unchanged and are never normalized.

### Two approaches to cross-agent policies

**Approach 1: List all agent-native names explicitly.** This is what the built-in templates use. No normalization required — policies work by matching every known name for each tool:

```yaml
# From the default template
- name: allow-safe-shell
  tools:
    # Canonical
    - "shell_execute"
    # Claude Code
    - "Bash"
    # Gemini CLI
    - "run_shell_command"
    # Windsurf
    - "run_command"
    # OpenAI Codex
    - "shell"
    - "local_shell"
    - "exec_command"
    # Generic globs
    - "shell_*"
    - "bash_*"
    - "command_*"
  action: allow
  conditions:
    shell_safe: true
    command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node, make]
```

**Approach 2: Enable `normalize_tools` and write canonical names only.** Shorter policies, but requires setting `agent_id` on every call:

```yaml
# Same rule, canonical names only
- name: allow-safe-shell
  tools: ["shell_execute"]
  action: allow
  conditions:
    shell_safe: true
    command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node, make]
```

```python
guard = Guard(policy="avakill.yaml", normalize_tools=True)
decision = guard.evaluate(tool="Bash", args={"command": "ls"}, agent_id="claude-code")
# "Bash" is normalized to "shell_execute" before rule matching
```

See the [API Reference](api-reference.md) for Python SDK details on `normalize_tools` and `ToolNormalizer`.

## Conditions

Conditions let you match rules based on the **arguments** passed to the tool call. Both condition types inspect argument values as case-insensitive substring matches.

### `args_match`

The rule matches only if **all** specified argument keys contain at least one of the given substrings (AND logic across keys, OR logic within each key's list).

```yaml
conditions:
  args_match:
    query: ["DROP", "DELETE", "TRUNCATE"]
```

This matches when the `query` argument (converted to a string, case-insensitive) contains `"drop"`, `"delete"`, or `"truncate"`.

Multiple keys require all of them to match:

```yaml
conditions:
  args_match:
    query: ["SELECT"]
    database: ["production"]
```

This only matches when `query` contains `"SELECT"` **and** `database` contains `"production"`.

### `args_not_match`

The condition **fails** if **any** argument key's value contains any of the specified substrings. This is the inverse of `args_match`.

```yaml
conditions:
  args_not_match:
    path: ["/tmp", "/var/tmp"]
```

This condition fails (rule does not match) if `path` contains `"/tmp"` or `"/var/tmp"`. Useful for "allow everything except" patterns:

```yaml
# Allow file deletion, but only in temp directories
- name: allow-temp-deletes
  tools: ["file_delete"]
  action: allow
  conditions:
    args_match:
      path: ["/tmp/", "/var/tmp/"]

# Block file deletion everywhere else
- name: block-other-deletes
  tools: ["file_delete"]
  action: deny
```

### Combining `args_match` and `args_not_match`

You can use both in the same rule. Both must be satisfied:

```yaml
conditions:
  args_match:
    command: ["git"]           # Must contain "git"
  args_not_match:
    command: ["push --force"]  # Must NOT contain "push --force"
```

### `shell_safe`

The `shell_safe` condition rejects commands containing shell metacharacters. When set to `true`, the rule only matches if the `command` (or `cmd`) argument contains **no shell metacharacters**.

```yaml
conditions:
  shell_safe: true
```

Detected metacharacter patterns:

| Category | Patterns |
|----------|----------|
| Pipes | `\|` |
| Redirects | `>`, `>>`, `<`, `<<` |
| Chaining | `;`, `&&`, `\|\|` |
| Subshells | `` ` ``, `$()` |
| Variable expansion | `${}` |
| Dangerous builtins | `eval`, `source`, `xargs` |

If metacharacters are found, the condition fails and the rule is skipped — falling through to subsequent rules (typically a catch-all deny). Default: `false` (disabled).

**Example:** Allow simple commands but deny anything with metacharacters:

```yaml
policies:
  - name: allow-safe-shell
    tools: ["shell_execute"]
    action: allow
    conditions:
      shell_safe: true

  - name: deny-everything-else
    tools: ["*"]
    action: deny
```

| Command | Result | Reason |
|---------|--------|--------|
| `echo hello` | Allowed | No metacharacters → `shell_safe` passes → matches `allow-safe-shell` |
| `echo hello \| sh` | Denied | Pipe detected → `shell_safe` fails → falls through to `deny-everything-else` |
| `cat file; rm -rf /` | Denied | Semicolon detected → `shell_safe` fails → falls through to deny |

### `command_allowlist`

The `command_allowlist` condition extracts the **first whitespace-delimited token** from the `command` (or `cmd`) argument and checks if it matches any entry in the list (case-insensitive, exact match).

```yaml
conditions:
  command_allowlist:
    - echo
    - ls
    - git
    - python
    - pip
```

Unlike `args_match` (substring matching), `command_allowlist` prevents prefix-smuggling attacks where a dangerous command appears to contain an allowed substring.

**Why this exists — the bypass that motivated it:**

```yaml
# VULNERABLE — uses args_match (substring)
conditions:
  args_match:
    command: ["echo"]
```

The command `env AVAKILL_POLICY=/dev/null echo bypassed` passes `args_match` because it contains the substring "echo" — but the actual command being executed is `env`, not `echo`.

```yaml
# SECURE — uses command_allowlist (first-token match)
conditions:
  command_allowlist: [echo, ls, git]
```

Now `env AVAKILL_POLICY=/dev/null echo bypassed` is rejected because the first token is `env`, which is not in the allowlist.

### Combining `shell_safe` and `command_allowlist`

For shell command policies, always combine both conditions with a catch-all deny. This is the recommended pattern:

```yaml
policies:
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

This provides two independent layers of defense:

1. **`command_allowlist`** ensures only known-good binaries can be invoked (blocks `env`, `bash -c`, etc.)
2. **`shell_safe`** ensures no metacharacter injection even in allowed commands (blocks `echo hello | sh`)

Both conditions must pass for the rule to match. If either fails, the rule is skipped and the catch-all deny applies.

### Matching behavior details

- Argument values are converted to strings with `str()` before matching.
- All comparisons are case-insensitive.
- If the specified argument key does not exist in the tool call, it is treated as an empty string (which won't match any substring).

## Rate Limiting

Rate limiting restricts how many times a tool can be called within a sliding time window.

```yaml
rate_limit:
  max_calls: 10
  window: "60s"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_calls` | int | Yes | Maximum number of calls allowed within the window. |
| `window` | string | Yes | Time window. Format: `<number><unit>` where unit is `s` (seconds), `m` (minutes), or `h` (hours). |

### Window syntax

| Value | Duration |
|-------|----------|
| `"30s"` | 30 seconds |
| `"5m"` | 5 minutes |
| `"1h"` | 1 hour |

### Behavior when exceeded

When the rate limit is exceeded:

1. The `evaluate()` method raises `RateLimitExceeded` (a subclass of `PolicyViolation`).
2. The decision has `allowed=False` and `action="deny"`.
3. The `reason` field contains: `"Rate limit exceeded: 10 calls per 60s"`.

```python
from avakill import Guard, RateLimitExceeded

guard = Guard(policy="avakill.yaml")

try:
    for i in range(100):
        guard.evaluate(tool="web_search", args={"q": f"query {i}"})
except RateLimitExceeded as e:
    print(e)
    # → AvaKill blocked 'web_search': Rate limit exceeded: 10 calls per 60s
    #   [policy: rate-limit-search]
```

### Implementation details

- Rate limits use a **sliding window** with an in-memory deque of timestamps.
- The window slides continuously — it is not reset at fixed intervals.
- Rate limits are tracked per tool name. When `agent_id` is set, counters are scoped per agent, so each agent gets an independent rate-limit counter per tool. Key format: `{agent_id}:{tool_name}` or just `{tool_name}`.
- Rate limit state is thread-safe (protected by a lock). By default, timestamps are stored in-memory and reset on process restart. For persistence across restarts, use the `SQLiteBackend`:

```python
from avakill.core.rate_limit_store import SQLiteBackend

backend = SQLiteBackend("avakill_rate_limits.db")
guard = Guard(policy="avakill.yaml", rate_limit_backend=backend)
```

This prevents agents from bypassing rate limits by triggering a restart.

## Environment Variable Substitution

Policy files support `${VAR_NAME}` syntax for substituting environment variables at load time:

```yaml
policies:
  - name: block-prod-writes
    tools: ["database_*"]
    action: deny
    conditions:
      args_match:
        connection_string: ["${PROD_DB_HOST}"]
    message: "Direct writes to ${ENV_NAME} database are blocked"
```

If `PROD_DB_HOST=prod-db.internal` and `ENV_NAME=production`, the policy is loaded as:

```yaml
conditions:
  args_match:
    connection_string: ["prod-db.internal"]
message: "Direct writes to production database are blocked"
```

If an environment variable is not set, the `${VAR_NAME}` placeholder is left as-is.

## Policy Evaluation Order

The full evaluation algorithm:

0. **Self-protection check** (if enabled). Runs before any user-defined rule. See [Self-Protection](#self-protection).
1. **Normalize tool name** (if `normalize_tools` enabled). See [Tool Normalization](#tool-normalization).
2. Iterate through `policies` in order.
3. For each rule, check if the tool name matches any pattern in `tools`.
4. If matched, check `conditions` (if any). Both `args_match` and `args_not_match` must be satisfied.
5. If conditions pass, check `rate_limit` (if any). If the rate limit is exceeded, raise `RateLimitExceeded`.
6. If all checks pass, return this rule's `action` as the decision. **Stop here.**
7. If no rule matches, return `default_action`.

```
tool_call("execute_sql", {"query": "DROP TABLE users"})
    │
    ├─ Rule 1: tools=["*_read"] → no match → next
    ├─ Rule 2: tools=["execute_sql"], args_match={"query": ["DROP"]}
    │          → tool matches ✓
    │          → condition matches ("DROP" found in query) ✓
    │          → action: deny → RETURN Decision(allowed=False)
    │
    └─ (remaining rules never checked)
```

### Self-Protection

Self-protection is a set of hardcoded checks that run **before** any user-defined policy rules. They cannot be overridden or relaxed by policy configuration.

When self-protection blocks a call, the returned decision has `policy_name="self-protection"` and the `reason` starts with `"Self-protection:"`.

| Category | What is blocked |
|----------|----------------|
| Policy file writes | Write/edit/delete tools targeting `avakill.yaml` or `avakill.yml` |
| Package uninstall | Shell commands matching `pip uninstall avakill`, `pipx uninstall avakill`, etc. |
| Approve command | Shell commands running `avakill approve` (only humans may activate policies) |
| Daemon shutdown | Shell commands running `avakill daemon stop`, `pkill avakill`, `systemctl stop avakill`, etc. |
| Source modification | Write tools or shell commands targeting `site-packages/avakill/` or `src/avakill/` |
| Hook binary tampering | Shell commands deleting, moving, or overwriting `avakill-hook-*` binaries |
| Hook config tampering | Write tools targeting agent config files (`.claude/settings.json`, `.gemini/hooks.json`, etc.) |

Policy file writes are redirected through a **staging workflow**: agents can write to `.proposed.yaml` instead. A human then runs `avakill approve` to activate the proposed policy.

Self-protection is enabled by default. Pass `self_protection=False` to `Guard()` only for testing:

```python
guard = Guard(policy="avakill.yaml", self_protection=False)  # testing only
```

## Examples

### Deny-by-default with explicit allowlist

The most secure pattern. Nothing runs unless you explicitly permit it.

```yaml
version: "1.0"
default_action: deny

policies:
  - name: allow-reads
    tools: ["*_read", "*_get", "*_list", "*_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "1m"

  - name: allow-safe-writes
    tools: ["*_write", "*_create", "*_update"]
    action: require_approval
```

### Allow-by-default with blocklist

For development or low-risk environments. Everything is allowed except explicit blocks.

```yaml
version: "1.0"
default_action: allow

policies:
  - name: block-drop-database
    tools: ["database_*", "sql_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP DATABASE", "DROP SCHEMA"]

  - name: block-rm-rf-root
    tools: ["shell_*", "bash_*"]
    action: deny
    conditions:
      args_match:
        cmd: ["rm -rf /"]

  - name: log-everything
    tools: ["all"]
    action: allow
    log: true
```

### Rate limiting expensive API calls

```yaml
version: "1.0"
default_action: deny

policies:
  - name: rate-limit-web-search
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"
    message: "Web searches are rate-limited to 10 per minute"

  - name: rate-limit-code-execution
    tools: ["code_execute", "run_code"]
    action: allow
    rate_limit:
      max_calls: 5
      window: "1m"

  - name: rate-limit-api-calls
    tools: ["api_*"]
    action: allow
    rate_limit:
      max_calls: 100
      window: "1h"
```

### Blocking destructive SQL

Block dangerous SQL keywords while allowing safe queries. Order matters — the deny rule must come before the allow rule for the same tools.

```yaml
version: "1.0"
default_action: deny

policies:
  - name: block-destructive-sql
    tools: ["execute_sql", "database_execute", "run_query"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL blocked. Use manual migration instead."

  - name: allow-safe-sql
    tools: ["execute_sql", "database_execute", "run_query"]
    action: allow
```

With this policy:

| Query | Decision | Reason |
|-------|----------|--------|
| `SELECT * FROM users` | Allowed | Matches `allow-safe-sql` (no destructive keywords) |
| `DROP TABLE users` | Denied | Matches `block-destructive-sql` (`DROP` found in query) |
| `DELETE FROM sessions WHERE expired = true` | Denied | Matches `block-destructive-sql` (`DELETE` found) |

### Blocking dangerous shell commands

```yaml
version: "1.0"
default_action: deny

policies:
  - name: block-dangerous-shells
    tools: ["shell_execute", "run_command", "execute_command", "bash"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "rm -r", "sudo", "chmod 777", "> /dev/", "mkfs", "dd if="]
    message: "Dangerous shell command blocked."

  - name: allow-safe-shells
    tools: ["shell_execute", "run_command", "execute_command", "bash"]
    action: allow
```

### Blocking file deletions outside temp directories

Use two rules: allow deletions in temp directories, deny everywhere else.

```yaml
version: "1.0"
default_action: deny

policies:
  - name: allow-temp-deletes
    tools: ["file_delete", "remove_file"]
    action: allow
    conditions:
      args_match:
        path: ["/tmp/", "/var/tmp/", "/scratch/"]

  - name: block-all-other-deletes
    tools: ["file_delete", "remove_file"]
    action: deny
    message: "File deletion is only allowed in temp directories"
```

### Requiring approval for financial operations

```yaml
version: "1.0"
default_action: deny

policies:
  - name: allow-balance-checks
    tools: ["get_balance", "list_transactions", "check_*"]
    action: allow

  - name: approve-transfers
    tools: ["transfer_funds", "send_payment", "create_invoice"]
    action: require_approval
    message: "Financial operations require human approval"

  - name: block-account-ops
    tools: ["close_account", "delete_account", "modify_limits"]
    action: deny
    message: "Account-level operations are blocked"
```

### Using environment variables for environment-specific policies

```yaml
version: "1.0"
default_action: deny

policies:
  - name: block-prod-mutations
    tools: ["database_*"]
    action: deny
    conditions:
      args_match:
        host: ["${PROD_DB_HOST}"]
        query: ["INSERT", "UPDATE", "DELETE", "DROP"]
    message: "Direct mutations to production database are blocked"

  - name: allow-database
    tools: ["database_*"]
    action: allow
```

Set `PROD_DB_HOST` per environment:

```bash
export PROD_DB_HOST="prod-db.internal.company.com"
```

### Cross-agent shell policy

When your policy must work across multiple AI coding agents, list all agent-native tool names alongside the canonical name. This is the pattern used by AvaKill's built-in templates:

```yaml
version: "1.0"
default_action: deny

policies:
  - name: block-dangerous-shell
    tools:
      # Canonical
      - "shell_execute"
      # Claude Code
      - "Bash"
      # Gemini CLI
      - "run_shell_command"
      # Windsurf
      - "run_command"
      # OpenAI Codex
      - "shell"
      - "local_shell"
      - "exec_command"
      # Generic globs
      - "shell_*"
      - "bash_*"
      - "command_*"
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777", "mkfs", "> /dev/"]
    message: "Dangerous shell command blocked."

  - name: allow-safe-shell
    tools:
      - "shell_execute"
      - "Bash"
      - "run_shell_command"
      - "run_command"
      - "shell"
      - "local_shell"
      - "exec_command"
      - "shell_*"
      - "bash_*"
      - "command_*"
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node, make]
```

### Starting from a template

AvaKill ships four policy templates. Use `avakill guide` to generate one interactively, or copy from `src/avakill/templates/`:

| Template | `default_action` | Description |
|----------|-------------------|-------------|
| `hooks` | `allow` | Blocks catastrophic ops, allows most else. Designed for agent hooks. |
| `default` | `deny` | Deny-by-default with read allows, rate limits, and safe-shell rules. |
| `strict` | `deny` | Explicit allowlist only. All writes require approval. |
| `permissive` | `allow` | Allows everything, logs all calls. For development and audit. |

All templates include agent-native tool names for Claude Code, Gemini CLI, Cursor, Windsurf, and OpenAI Codex.

## Hot Reloading

Policies can be reloaded at runtime without restarting your application:

```python
guard = Guard(policy="avakill.yaml")

# Later, after editing the policy file:
guard.reload_policy()

# Or reload from a different path:
guard.reload_policy("policies/updated.yaml")
```

This replaces the policy engine atomically. In-flight evaluations complete with the old policy; new evaluations use the new one.

## Policy Cascade

AvaKill supports multi-level policy files that are automatically discovered and merged. This lets system administrators set organization-wide defaults while individual projects can add their own rules.

### Discovery Levels

Policy files are discovered in this order (highest priority first for deny rules):

| Level | Path | Description |
|-------|------|-------------|
| **System** | `/etc/avakill/policy.yaml` | Organization-wide defaults. Managed by admins. |
| **Global** | `~/.config/avakill/policy.yaml` | User-wide defaults. |
| **Project** | `.avakill/policy.yaml`, `avakill.yaml`, or `avakill.yml` | Project-specific rules. Walks up the directory tree. |
| **Local** | `.avakill/policy.local.yaml` | Local overrides. Gitignored. |

### Merge Semantics

When multiple policy files are found, they are merged with **deny-wins** semantics:

- **Default action:** `"deny"` if any level sets it to deny
- **Deny rules:** Unioned across all levels (all deny rules from all files apply)
- **Allow rules:** Kept only if no higher-level `hard` enforcement denies the same tools
- **Rate limits:** The most restrictive (lowest `max_calls`) wins
- **Hard enforcement** at a higher level cannot be relaxed by lower levels

### Example

System admin sets a hard deny on destructive SQL:

```yaml
# /etc/avakill/policy.yaml (system level)
version: "1.0"
default_action: deny

policies:
  - name: "system-block-destructive-sql"
    tools: ["execute_sql"]
    action: deny
    enforcement: hard
    conditions:
      args_match:
        query: ["DROP", "TRUNCATE"]
```

Project adds its own allow rules:

```yaml
# .avakill/policy.yaml (project level)
version: "1.0"
default_action: deny

policies:
  - name: "allow-safe-sql"
    tools: ["execute_sql"]
    action: allow
```

Result: `SELECT` queries are allowed, but `DROP` and `TRUNCATE` are blocked — the system-level hard deny cannot be overridden.

### Using the Cascade

```python
from avakill.core.cascade import PolicyCascade

cascade = PolicyCascade()

# Discover all policy files
levels = cascade.discover()
# → [("system", Path("/etc/avakill/policy.yaml")), ("project", Path("avakill.yaml"))]

# Load and merge
config = cascade.load()
```

The `avakill daemon` and hook adapters use the cascade automatically.

## Sandbox Configuration

> **Future release.** OS-level sandboxing is defined in the policy schema but not yet enforced at runtime. The fields below are accepted and validated but have no effect until a future version.

The optional `sandbox` top-level field configures OS-level process sandboxing (Landlock on Linux, sandbox-exec on macOS):

```yaml
version: "1.0"
default_action: deny

sandbox:
  allow_paths:
    read:
      - "/usr"
      - "/etc"
      - "${HOME}/.config"
    write:
      - "/tmp"
      - "${HOME}/projects"
    execute:
      - "/usr/bin"
      - "/usr/local/bin"
  allow_network:
    connect:
      - "api.example.com:443"
      - "registry.npmjs.org:443"
    bind: []
  resource_limits:
    max_memory_mb: 512
    max_open_files: 256
    max_processes: 50
    timeout_seconds: 300
  inherit_env: true
  inject_hooks: true

policies:
  - name: allow-reads
    tools: ["*_read"]
    action: allow
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_paths.read` | list[string] | `[]` | Filesystem paths the sandboxed process can read. |
| `allow_paths.write` | list[string] | `[]` | Filesystem paths the sandboxed process can write. |
| `allow_paths.execute` | list[string] | `[]` | Filesystem paths the sandboxed process can execute. |
| `allow_network.connect` | list[string] | `[]` | Network endpoints the sandboxed process can connect to. |
| `allow_network.bind` | list[string] | `[]` | Network endpoints the sandboxed process can bind/listen on. |
| `resource_limits.max_memory_mb` | int | `null` | Maximum memory in megabytes. |
| `resource_limits.max_open_files` | int | `null` | Maximum number of open file descriptors. |
| `resource_limits.max_processes` | int | `null` | Maximum number of child processes. |
| `resource_limits.timeout_seconds` | int | `null` | Maximum execution time in seconds. |
| `inherit_env` | bool | `true` | Whether the sandboxed process inherits the parent environment. |
| `inject_hooks` | bool | `true` | Whether AvaKill hook binaries are injected into the sandbox. |
