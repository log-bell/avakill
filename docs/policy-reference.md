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
| `version` | string | No | `"1.0"` | Schema version. Must be `"1.0"`. |
| `default_action` | string | No | `"deny"` | Action when no rule matches. Must be `"allow"` or `"deny"`. |
| `policies` | list | Yes | — | Ordered list of policy rules, evaluated top-to-bottom. |
| `notifications` | object | No | `{}` | Notification configuration (reserved for future use). |

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
- Rate limits are tracked per tool name, not per rule.
- Rate limit state is thread-safe (protected by a lock) but not persisted across process restarts.

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

1. Iterate through `policies` in order.
2. For each rule, check if the tool name matches any pattern in `tools`.
3. If matched, check `conditions` (if any). Both `args_match` and `args_not_match` must be satisfied.
4. If conditions pass, check `rate_limit` (if any). If the rate limit is exceeded, raise `RateLimitExceeded`.
5. If all checks pass, return this rule's `action` as the decision. **Stop here.**
6. If no rule matches, return `default_action`.

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
