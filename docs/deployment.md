# Deployment Guide

This guide covers deploying AvaKill from local development through staging to production, including Docker and systemd patterns.

## Development

### Install

```bash
pip install avakill

# With framework integrations
pip install avakill[openai]        # OpenAI wrapper
pip install avakill[anthropic]     # Anthropic wrapper
pip install avakill[langchain]     # LangChain handler
pip install avakill[mcp]           # MCP proxy
pip install avakill[all]           # Everything
```

### Initialize a Policy

```bash
avakill init
# Choose: default, strict, or permissive template
# Creates avakill.yaml in the current directory
```

The `permissive` template is best for development — it allows everything but logs all calls, so you can see what the agent does before tightening policies:

```bash
avakill init --template permissive
```

### Enable Logging

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

logger = SQLiteLogger("avakill_audit.db")
guard = Guard(policy="avakill.yaml", logger=logger)
```

### Monitor with the Dashboard

```bash
avakill dashboard --db avakill_audit.db
```

Watch tool calls flow through in real-time. Use this to identify which tools your agent uses and which policies you need.

## Staging

### Use a Strict Policy

Switch from the permissive template to a strict one:

```bash
avakill init --template strict --output avakill-staging.yaml
```

Or write a custom policy based on what you observed in development. See the [Policy Reference](policy-reference.md) for the full YAML schema.

### Validate Before Deploy

```bash
avakill validate avakill.yaml
# Exits 0 if valid, 1 if invalid — safe for CI
```

### Enable Policy Signing

For staging, HMAC signing is sufficient:

```bash
# Generate and set a signing key
avakill sign --generate-key
export AVAKILL_POLICY_KEY=<generated-key-hex>

# Sign the policy
avakill sign avakill.yaml
```

### Connect Observability

Choose OpenTelemetry or Prometheus (or both):

```bash
# OpenTelemetry
pip install avakill[otel] opentelemetry-sdk opentelemetry-exporter-otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_SERVICE_NAME=my-agent

# Prometheus
pip install avakill[metrics]
avakill metrics --port 9090
```

See the [Observability Guide](observability.md) for full setup.

### Review Audit Logs for False Positives

```bash
# Show all denied events
avakill logs --denied-only

# Filter by time window
avakill logs --denied-only --since 24h

# Export as JSON for analysis
avakill logs --denied-only --json > denied.json
```

Tune your policy rules based on what gets denied. Common issues:

- Glob patterns too broad (blocking legitimate tools)
- Argument matching too aggressive (blocking safe SQL)
- Rate limits too tight (blocking burst patterns)

## Production

### Ed25519 Signing

Use asymmetric signing so the private key never exists on production machines:

```bash
# On your CI/deploy machine:
avakill keygen
export AVAKILL_SIGNING_KEY=<private-key-hex>  # Store in secrets manager
avakill sign --ed25519 avakill.yaml

# Deploy avakill.yaml + avakill.yaml.sig together

# On production:
export AVAKILL_VERIFY_KEY=<public-key-hex>
```

See the [Security Hardening Guide](security-hardening.md) for complete key management guidance.

### OS-Level Hardening

```bash
pip install avakill[hardened]
sudo avakill harden avakill.yaml
avakill check-hardening avakill.yaml
```

### Rate Limit Persistence

By default, rate limit counters are in-memory and reset on restart. For production, use the SQLite backend:

```python
from avakill import Guard
from avakill.core.rate_limit_store import SQLiteBackend

backend = SQLiteBackend("avakill_rate_limits.db")
guard = Guard(policy="avakill.yaml", rate_limit_backend=backend)
```

This persists rate limit timestamps across restarts, preventing agents from bypassing limits by triggering a restart.

### Hot-Reload with File Watcher

Reload policies without restarting your application:

```python
# Manual reload
guard.reload_policy()

# Automatic file watching
watcher = guard.watch()
await watcher.start()
# Policy reloads automatically when avakill.yaml changes on disk

# Or with the dashboard
avakill dashboard --policy avakill.yaml --watch
```

### Prometheus Endpoint for Alerting

```bash
avakill metrics --port 9090 --host 0.0.0.0
```

Key metrics to alert on:

| Metric | Alert condition | Meaning |
|--------|----------------|---------|
| `avakill_violations_total` | Spike above baseline | Agent hitting new denials |
| `avakill_self_protection_blocks_total` | Any increase | Agent trying to tamper |
| `avakill_evaluation_duration_seconds` | P99 > 10ms | Policy may be too large |

### Docker Deployment

Use the hardened Docker Compose template:

```bash
cp examples/docker-compose.hardened.yml docker-compose.yml
```

Key security features in the template:

```yaml
services:
  avakill:
    read_only: true           # Immutable filesystem
    tmpfs: [/tmp]             # Writable temp only
    cap_drop: [ALL]           # Drop all capabilities
    cap_add: [NET_BIND_SERVICE]
    security_opt:
      - seccomp=seccomp.json
    user: "1000:1000"         # Non-root
    deploy:
      resources:
        limits:
          memory: 256m
          cpus: "0.5"
```

Generate the seccomp profile:

```bash
avakill harden --seccomp -o seccomp.json
```

### systemd Service

Example service file (also available in `examples/systemd/`):

```ini
[Unit]
Description=AvaKill MCP Proxy
After=network.target

[Service]
Type=simple
User=avakill
Group=avakill
ExecStart=/usr/local/bin/avakill mcp-proxy \
    --upstream-cmd /usr/local/bin/my-mcp-server \
    --policy /etc/avakill/avakill.yaml \
    --log-db /var/lib/avakill/audit.db
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/avakill
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Install and start:

```bash
sudo cp avakill.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now avakill
```

## MCP Deployment

### Claude Desktop

Add to `claude_desktop_config.json`:

```jsonc
{
  "mcpServers": {
    "my-server": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "my_server.py",
        "--policy", "/path/to/avakill.yaml",
        "--log-db", "/path/to/audit.db"
      ]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "node",
        "--upstream-args", "server.js",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### Multi-Server Proxy

Run multiple MCP servers through separate AvaKill proxies, each with its own policy:

```jsonc
{
  "mcpServers": {
    "database": {
      "command": "avakill",
      "args": ["mcp-proxy", "--upstream-cmd", "python", "--upstream-args", "db_server.py", "--policy", "db-policy.yaml"]
    },
    "filesystem": {
      "command": "avakill",
      "args": ["mcp-proxy", "--upstream-cmd", "python", "--upstream-args", "fs_server.py", "--policy", "fs-policy.yaml"]
    }
  }
}
```

For more MCP details, see the [MCP Proxy Guide](mcp-proxy.md).

## Environment Variables

All AvaKill configuration can be set via environment variables:

| Variable | Description | Used by |
|----------|-------------|---------|
| `AVAKILL_POLICY_KEY` | HMAC signing key (hex) | Guard, `avakill sign`, `avakill verify` |
| `AVAKILL_SIGNING_KEY` | Ed25519 private key (hex) | `avakill sign --ed25519` |
| `AVAKILL_VERIFY_KEY` | Ed25519 public key (hex) | Guard, `avakill verify` |

### Policy Variable Substitution

Use `${VAR_NAME}` in your YAML policies for environment-specific values:

```yaml
policies:
  - name: "rate-limit-api"
    tools: ["api_call"]
    action: allow
    rate_limit:
      max_calls: ${API_RATE_LIMIT}
      window: "60s"
```

```bash
export API_RATE_LIMIT=100  # Production
export API_RATE_LIMIT=1000 # Development (more lenient)
```

---

## Further Reading

- **[Getting Started](getting-started.md)** — quick setup walkthrough
- **[Security Hardening](security-hardening.md)** — signing, OS hardening, C hooks
- **[Observability](observability.md)** — OTel + Prometheus setup
- **[MCP Proxy](mcp-proxy.md)** — detailed MCP deployment guide
- **[CLI Reference](cli-reference.md)** — all commands
