<!-- AVAKILL-CONTEXT-START -->
## AvaKill — AI Agent Safety Firewall

This project uses [AvaKill](https://github.com/log-bell/avakill) to enforce safety policies on AI agent tool calls. The policy file is `/private/var/folders/pn/c1sqxh6s20d4w4b1zqzbq4dw0000gn/T/pytest-of-ablecoffee/pytest-289/test_init_mentions_audit_loggi0/avakill.yaml`.

### Policy format

Policies are YAML. Rules are evaluated top-to-bottom — **first match wins**.

```yaml
version: "1.0"
default_action: deny  # or allow

policies:
  - name: rule-name
    tools: ["glob_pattern*", "exact_name"]  # fnmatch patterns
    action: allow | deny | require_approval
    conditions:                              # optional
      args_match:
        arg_name: ["substring1", "substring2"]  # case-insensitive
      shell_safe: true                       # reject metacharacters
      command_allowlist: [echo, ls, git]     # first token must be in list
    rate_limit:                              # optional
      max_calls: 10
      window: "60s"                          # 10s, 5m, 1h
    message: "Human-readable denial reason"
```

### Common patterns

- **Block destructive ops**: `tools: ["delete_*", "drop_*"]` with `action: deny`
- **Allow reads**: `tools: ["search_*", "get_*", "read_*", "list_*"]` with `action: allow`
- **Block dangerous shell**: `tools: ["shell_*"]` + `args_match: {command: ["rm -rf", "sudo"]}` with `action: deny`
- **Safe shell allowlist**: `tools: ["shell_*"]` + `shell_safe: true` + `command_allowlist: [echo, ls, git, python]`
- **Rate limit**: `rate_limit: {max_calls: 10, window: "60s"}`

### Commands

- `avakill validate /private/var/folders/pn/c1sqxh6s20d4w4b1zqzbq4dw0000gn/T/pytest-of-ablecoffee/pytest-289/test_init_mentions_audit_loggi0/avakill.yaml` — check policy syntax
- `avakill dashboard` — real-time monitoring
- `avakill schema --format=prompt` — generate a full policy-writing prompt
- `avakill guide policy` — interactive policy creation wizard

### Rules

- Do NOT modify or delete `/private/var/folders/pn/c1sqxh6s20d4w4b1zqzbq4dw0000gn/T/pytest-of-ablecoffee/pytest-289/test_init_mentions_audit_loggi0/avakill.yaml` unless the user explicitly asks
- When writing policies, put specific deny rules BEFORE general allow rules
- Always validate after changes: `avakill validate /private/var/folders/pn/c1sqxh6s20d4w4b1zqzbq4dw0000gn/T/pytest-of-ablecoffee/pytest-289/test_init_mentions_audit_loggi0/avakill.yaml`
<!-- AVAKILL-CONTEXT-END -->
