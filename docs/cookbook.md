# Cookbook: Real-World Policies

Each recipe is self-contained: a real scenario, the policy YAML, integration code, and verification steps.

## Protecting a Data Pipeline Agent

**Problem:** Your agent runs SQL queries against a production database. It should be able to read data and insert rows, but never drop tables, delete data, or alter schemas.

**Policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  # Block destructive SQL first (before any allow rules)
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*", "sql_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]
    message: "Destructive SQL blocked. Use a manual migration."

  # Rate-limit write operations
  - name: "rate-limit-writes"
    tools: ["execute_sql", "database_*"]
    action: allow
    conditions:
      args_match:
        query: ["INSERT", "UPDATE"]
    rate_limit:
      max_calls: 50
      window: "60s"

  # Allow all reads
  - name: "allow-reads"
    tools: ["execute_sql", "database_*", "sql_*"]
    action: allow
```

**Integration:**

```python
from avakill import Guard, protect

guard = Guard(policy="avakill.yaml")

@protect(guard=guard)
def execute_sql(query: str) -> list:
    return db.execute(query).fetchall()

# Works:
execute_sql("SELECT * FROM users WHERE active = true")

# Blocked:
execute_sql("DROP TABLE users")  # → PolicyViolation

# Rate-limited after 50 calls/minute:
for i in range(60):
    execute_sql(f"INSERT INTO logs VALUES ({i})")  # 51st call → RateLimitExceeded
```

---

## Securing a Code Assistant (Claude Code / Cursor)

**Problem:** Your code assistant has MCP tools for file operations and shell commands. It should read freely but not delete files, run dangerous commands, or modify system files.

**Policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  # Block dangerous shell commands
  - name: "block-dangerous-shells"
    tools: ["shell_execute", "run_command", "bash"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "chmod 777", "sudo", "> /dev/", "mkfs", "dd if="]
    message: "Dangerous shell command blocked."

  # Block writes to system directories
  - name: "block-system-writes"
    tools: ["file_write", "write_file", "create_file"]
    action: deny
    conditions:
      args_match:
        path: ["/etc/", "/usr/", "/bin/", "/sbin/", "/var/log/"]
    message: "Cannot write to system directories."

  # Allow file reads everywhere
  - name: "allow-reads"
    tools: ["file_read", "read_file", "list_directory", "search_*", "*_get"]
    action: allow

  # Allow writes to project directory (rate-limited)
  - name: "allow-project-writes"
    tools: ["file_write", "write_file", "create_file"]
    action: allow
    rate_limit:
      max_calls: 30
      window: "60s"

  # Allow safe shell commands (rate-limited)
  - name: "allow-safe-shells"
    tools: ["shell_execute", "run_command", "bash"]
    action: allow
    rate_limit:
      max_calls: 20
      window: "60s"
```

**MCP proxy setup** (Claude Desktop):

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "filesystem": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "npx",
        "--upstream-args", "@modelcontextprotocol/server-filesystem /home/user/projects",
        "--policy", "/home/user/.config/avakill/code-assistant.yaml",
        "--log-db", "/home/user/.config/avakill/audit.db"
      ]
    }
  }
}
```

---

## E-Commerce Order Management

**Problem:** An agent manages orders — reading order details, processing refunds, updating statuses. It should never bulk-delete orders, and refund processing should be rate-limited.

**Policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  # Block bulk deletions
  - name: "block-bulk-delete"
    tools: ["delete_order", "remove_order", "cancel_order"]
    action: deny
    conditions:
      args_match:
        batch: ["true"]
    message: "Bulk order deletions require manual approval."

  # Rate-limit refund processing
  - name: "rate-limit-refunds"
    tools: ["process_refund", "issue_refund"]
    action: allow
    rate_limit:
      max_calls: 5
      window: "5m"

  # Require approval for order cancellation
  - name: "approve-cancellation"
    tools: ["cancel_order"]
    action: require_approval
    message: "Order cancellation requires human approval."

  # Allow read operations freely
  - name: "allow-reads"
    tools: ["get_order", "list_orders", "search_orders", "order_status"]
    action: allow

  # Allow status updates
  - name: "allow-status-update"
    tools: ["update_order_status"]
    action: allow
```

**Integration:**

```python
from avakill import Guard

guard = Guard(policy="ecommerce-policy.yaml")

def handle_agent_action(tool_name: str, args: dict):
    decision = guard.evaluate(tool=tool_name, args=args)

    if decision.action == "require_approval":
        # Queue for human review
        queue_for_approval(tool_name, args, decision.reason)
        return {"status": "pending_approval"}

    if not decision.allowed:
        return {"error": decision.reason}

    return execute_tool(tool_name, args)
```

---

## Multi-Agent System with Shared Policy

**Problem:** Multiple agents share tools but need different rate limits and tracking. You want per-agent audit trails and the ability to query by agent.

**Policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  # Block destructive operations for all agents
  - name: "block-destructive"
    tools: ["delete_*", "drop_*", "destroy_*"]
    action: deny

  # Rate-limit API calls (per-agent via agent_id)
  - name: "rate-limit-api"
    tools: ["api_call", "http_request"]
    action: allow
    rate_limit:
      max_calls: ${API_RATE_LIMIT}
      window: "60s"

  # Allow common tools
  - name: "allow-common"
    tools: ["search_*", "*_read", "*_get", "*_list", "calculate_*"]
    action: allow
```

**Integration:**

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

logger = SQLiteLogger("multi_agent_audit.db")
guard = Guard(policy="shared-policy.yaml", logger=logger)

# Each agent gets its own session
def run_agent(agent_name: str, tasks: list):
    with guard.session(agent_id=agent_name) as session:
        for task in tasks:
            decision = session.evaluate(
                tool=task["tool"],
                args=task["args"],
            )
            if decision.allowed:
                execute_tool(task["tool"], task["args"])
            else:
                log_denial(agent_name, task, decision)
        print(f"{agent_name}: {session.call_count} calls")

# Run agents
run_agent("research-agent", research_tasks)
run_agent("analysis-agent", analysis_tasks)
```

**Query audit logs by agent:**

```bash
# All events from a specific agent
avakill logs --agent research-agent

# Denied events by agent
avakill logs --agent analysis-agent --denied-only

# Export for analysis
avakill logs --agent research-agent --json > research-audit.json
```

---

## CI/CD Pipeline Safety

**Problem:** An AI agent manages deployments. It should be able to deploy and monitor, but never delete infrastructure, and deployments should be rate-limited to prevent runaway deploys.

**Policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  # Block infrastructure deletion
  - name: "block-infra-delete"
    tools: ["terraform_*", "aws_*", "gcp_*", "azure_*"]
    action: deny
    conditions:
      args_match:
        command: ["destroy", "delete", "terminate", "deregister"]
    message: "Infrastructure deletion requires manual approval."

  # Rate-limit deployments
  - name: "rate-limit-deploy"
    tools: ["deploy", "deploy_*", "kubectl_apply"]
    action: allow
    rate_limit:
      max_calls: 3
      window: "1h"

  # Allow monitoring and status checks
  - name: "allow-monitoring"
    tools: ["get_*", "list_*", "describe_*", "status_*", "health_*"]
    action: allow

  # Allow terraform plan (read-only)
  - name: "allow-plan"
    tools: ["terraform_*"]
    action: allow
    conditions:
      args_match:
        command: ["plan", "show", "output", "state list"]
```

**Validate policy in CI:**

```bash
# Add to your CI pipeline
avakill validate avakill.yaml
```

**Verify signature in CI:**

```bash
export AVAKILL_VERIFY_KEY=${{ secrets.AVAKILL_VERIFY_KEY }}
avakill verify avakill.yaml
```

---

## Audit & Compliance

**Problem:** Your compliance team needs to review all agent actions, track denial rates, and export logs for auditors.

**Setup:**

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

# Enable comprehensive logging
logger = SQLiteLogger("/var/lib/avakill/compliance-audit.db")
guard = Guard(policy="avakill.yaml", logger=logger)
```

**Export logs as JSON:**

```bash
# All events from the last 7 days
avakill logs --since 7d --json > weekly-audit.json

# Only denied events
avakill logs --denied-only --since 30d --json > monthly-denials.json

# By specific tool
avakill logs --tool "execute_sql" --since 7d --json > sql-audit.json
```

**Dashboard monitoring:**

```bash
# Live monitoring
avakill dashboard --db /var/lib/avakill/compliance-audit.db
```

**Prometheus alerting on denial spikes:**

```bash
# Start metrics endpoint
avakill metrics --port 9090
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: avakill
    static_configs:
      - targets: ["localhost:9090"]

# Alert rules
groups:
  - name: avakill
    rules:
      - alert: HighDenialRate
        expr: rate(avakill_violations_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AvaKill denial rate above 10/min"

      - alert: SelfProtectionTriggered
        expr: increase(avakill_self_protection_blocks_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Agent attempted to tamper with AvaKill"
```

---

## Hook Setup for Claude Code

**Problem:** You want to protect Claude Code from executing dangerous tool calls without modifying any code or MCP configuration.

**Setup:**

```bash
# 1. Start the daemon with your policy
avakill daemon start --policy avakill.yaml

# 2. Install the Claude Code hook
avakill hook install --agent claude-code

# 3. Verify installation
avakill hook list
# → claude-code: Detected=yes, Hook Installed=yes
```

**Verification:**

```bash
# Check daemon is running
avakill daemon status

# Test with a dangerous command — should be blocked
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent claude-code
echo $?  # → 2 (denied)

# Test with a safe command — should pass
echo '{"tool": "Read", "args": {"file_path": "README.md"}}' | avakill evaluate --agent claude-code
echo $?  # → 0 (allowed)
```

**Policy:** Use canonical tool names — the hook automatically translates Claude Code's native names (`Bash`, `Read`, `Write`) to canonical names (`shell_execute`, `file_read`, `file_write`):

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "block-dangerous-shells"
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777", "> /dev/"]

  - name: "allow-reads"
    tools: ["file_read", "file_search", "content_search", "file_list"]
    action: allow

  - name: "allow-writes"
    tools: ["file_write", "file_edit"]
    action: allow
    rate_limit:
      max_calls: 30
      window: "60s"

  - name: "allow-safe-shells"
    tools: ["shell_execute"]
    action: allow
    rate_limit:
      max_calls: 20
      window: "60s"
```

---

## Writing Policies with Canonical Tool Names

**Problem:** You use multiple AI coding agents and want one policy that works across all of them.

**Key insight:** AvaKill's `ToolNormalizer` translates agent-native tool names to canonical names. Write policies using canonical names and they work everywhere.

**Canonical tool name reference:**

| Canonical Name | Claude Code | Gemini CLI | Cursor | Windsurf |
|---------------|-------------|------------|--------|----------|
| `shell_execute` | `Bash` | `run_shell_command` | `shell_command` | `run_command` |
| `file_read` | `Read` | `read_file` | `read_file` | `read_code` |
| `file_write` | `Write` | `write_file` | — | `write_code` |
| `file_edit` | `Edit` / `MultiEdit` | `edit_file` | — | — |
| `file_search` | `Glob` | — | — | — |
| `content_search` | `Grep` | — | — | — |
| `web_fetch` | `WebFetch` | — | — | — |
| `web_search` | `WebSearch` | — | — | — |

**Universal policy:**

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "block-dangerous-shells"
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777", "mkfs", "> /dev/"]
    message: "Dangerous shell command blocked."

  - name: "allow-all-reads"
    tools: ["file_read", "file_search", "content_search", "file_list", "web_search", "web_fetch"]
    action: allow

  - name: "rate-limit-writes"
    tools: ["file_write", "file_edit"]
    action: allow
    rate_limit:
      max_calls: 50
      window: "60s"

  - name: "rate-limit-shells"
    tools: ["shell_execute"]
    action: allow
    rate_limit:
      max_calls: 20
      window: "60s"
```

Deploy to all agents:

```bash
avakill daemon start --policy universal-policy.yaml
avakill hook install --agent all
```

---

## Multi-Level Policy Cascade

**Problem:** Your security team needs organization-wide deny rules that individual projects cannot override, but projects should be able to add their own allow rules.

**System-level policy** (`/etc/avakill/policy.yaml`) — managed by admins:

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "org-block-destructive"
    tools: ["shell_execute"]
    action: deny
    enforcement: hard
    conditions:
      args_match:
        command: ["rm -rf /", "mkfs", "dd if=/dev/zero"]
    message: "Blocked by organization policy"

  - name: "org-block-network-exfil"
    tools: ["shell_execute"]
    action: deny
    enforcement: hard
    conditions:
      args_match:
        command: ["curl", "wget", "nc", "scp"]
    message: "Network commands blocked by organization policy"
```

**Project-level policy** (`avakill.yaml`) — managed by the team:

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "allow-git"
    tools: ["shell_execute"]
    action: allow
    conditions:
      args_match:
        command: ["git"]

  - name: "allow-reads"
    tools: ["file_read", "file_search", "content_search"]
    action: allow

  - name: "allow-writes"
    tools: ["file_write", "file_edit"]
    action: allow
```

**Result:** The project allows `git` commands and file operations, but the system-level hard deny on `rm -rf /`, `curl`, etc. cannot be overridden. The cascade merges both levels automatically.

---

## OS-Level Enforcement

**Problem:** Policy-level enforcement runs in userspace and could theoretically be bypassed. You want kernel-level restrictions as an additional layer.

### Landlock (Linux)

```bash
# Preview restrictions (dry-run)
avakill enforce landlock --policy avakill.yaml --dry-run
# Shows which filesystem operations would be restricted

# Apply (irreversible for the process)
avakill enforce landlock --policy avakill.yaml
```

Landlock translates deny rules into filesystem access restrictions:
- `file_write` deny → blocks `WRITE_FILE`, `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM`
- `file_delete` deny → blocks `REMOVE_FILE`, `REMOVE_DIR`
- `shell_execute` deny → blocks `EXECUTE`

### sandbox-exec (macOS)

```bash
# Generate SBPL profile
avakill enforce sandbox --policy avakill.yaml --output avakill.sb

# Run agent under sandbox
sandbox-exec -f avakill.sb python my_agent.py
```

### Tetragon (Kubernetes)

```bash
# Generate TracingPolicy
avakill enforce tetragon --policy avakill.yaml --output tetragon-policy.yaml

# Deploy
kubectl apply -f tetragon-policy.yaml
```

Tetragon monitors kernel syscalls via kprobes and kills processes that violate deny rules with `Sigkill`.

---

## Compliance Assessment Workflow

**Problem:** Your compliance team needs to verify that your AI agent deployment meets regulatory requirements.

### Generate Reports

```bash
# SOC 2 Type II assessment
avakill compliance report --framework soc2 --policy avakill.yaml

# All frameworks at once
avakill compliance report --framework all --policy avakill.yaml --format json --output compliance-report.json

# Markdown for documentation
avakill compliance report --framework eu-ai-act --policy avakill.yaml --format markdown --output eu-ai-act-report.md
```

### Identify Gaps

```bash
avakill compliance gaps --policy avakill.yaml
```

This shows only failing or partial controls with actionable recommendations.

### Common Gap Fixes

| Gap | Fix |
|-----|-----|
| "No deny-by-default" | Set `default_action: deny` |
| "No rate limiting" | Add `rate_limit` to high-frequency rules |
| "No audit logging" | Add `SQLiteLogger` to your Guard |
| "No policy signing" | Run `avakill keygen` and `avakill sign` |
| "No self-protection" | Ensure `self_protection=True` (default) |
| "No human oversight" | Add `require_approval` rules for sensitive operations |

### Approval Workflow

For `require_approval` rules:

```bash
# Agent triggers a tool call that requires approval
# → Approval request is created automatically

# Admin reviews and approves
avakill approvals list
avakill approvals grant abc123-request-id --approver admin

# Or rejects
avakill approvals reject abc123-request-id --approver admin
```

Approvals expire after 1 hour by default. Expired approvals are automatically cleaned up.

---

## Further Reading

- **[Policy Reference](policy-reference.md)** — full YAML schema and pattern matching
- **[Framework Integrations](internal/framework-integrations.md)** — OpenAI, Anthropic, LangChain wrappers
- **[Deployment](internal/deployment.md)** — production deployment patterns
- **[Troubleshooting](internal/troubleshooting.md)** — common policy issues
