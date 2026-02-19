# Generate AvaKill Policies with Any LLM

Copy the prompt below and paste it into any LLM (ChatGPT, Claude, Gemini, Llama, etc.) to generate a valid AvaKill policy. Then describe what your agent does and what tools it has access to.

> **Tip:** For the most up-to-date version of this prompt (including the latest schema), run:
>
> ```bash
> avakill schema --format=prompt
> ```
>
> You can also customize it with your actual tool names:
>
> ```bash
> avakill schema --format=prompt --tools="file_read,shell_exec,db_query" --use-case="code assistant"
> ```

---

## The Prompt

````
You are generating a YAML policy file for AvaKill, an open-source safety firewall for AI agents. The policy defines rules that intercept and evaluate tool calls before they execute. AvaKill enforces these rules deterministically — no LLM is involved at runtime.

Your output must be a single valid YAML document.

### Policy Structure

```yaml
version: "1.0"              # Required, must be "1.0"
default_action: deny         # "allow" or "deny" — applied when no rule matches

policies:                    # Ordered list of rules, evaluated top-to-bottom
  - name: "rule-name"       # Human-readable rule name
    tools:                   # Tool patterns (glob syntax: *, shell_*, *_read)
      - "tool_pattern"
    action: allow            # "allow", "deny", or "require_approval"
    conditions:              # Optional argument matching
      args_match:
        arg_name: ["substring1", "substring2"]  # Case-insensitive substring
      args_not_match:
        arg_name: ["blocked_substring"]
      shell_safe: true                           # Reject shell metacharacters
      command_allowlist: ["echo", "ls", "git"]   # First-token exact match
    rate_limit:              # Optional rate limiting
      max_calls: 10
      window: "60s"          # Duration: <number>[s|m|h]
    message: "Explanation"   # Optional, shown in audit logs
    log: true                # Optional, defaults to true
```

### Shell Safety

For any rule that matches shell/command execution tools (`shell_execute`, `shell_*`, `bash_*`, `command_*`), always use both `shell_safe` and `command_allowlist`:

- `shell_safe: true` rejects commands containing shell metacharacters (pipes `|`, redirects `>`, chaining `;` `&&` `||`, subshells `` ` `` `$()`, expansion `${}`, dangerous builtins `eval`/`source`/`xargs`).
- `command_allowlist: [...]` extracts the first whitespace-delimited token and matches it exactly (case-insensitive). This prevents prefix-smuggling like `env VAR=val echo bypassed`.
- Always combine both conditions together on shell allow rules.
- Always pair shell allow rules with a catch-all deny rule after them.

Example:

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

### Key Rules

1. **First-match-wins**: Rules are evaluated top-to-bottom. First matching rule is applied.
2. **Glob patterns**: `*` matches any characters. `shell_*` matches `shell_execute`, etc.
3. **Order matters**: Put specific deny rules BEFORE broader allow rules for the same tools.
4. **args_match**: Case-insensitive substring matching against stringified argument values.
5. **Rate limit window**: Must be a number + unit: `60s`, `5m`, `1h`. No spaces.
6. **Shell commands**: Always use `shell_safe: true` + `command_allowlist` instead of `args_match` on the command field.
7. **`args_match` is substring matching**: Use `command_allowlist` for matching the command binary name — `args_match` will match substrings anywhere in the argument.

### Common Mistakes

- Putting allow rules before deny rules for the same tools (allow matches first, deny never fires)
- Using `default_action: allow` without a catch-all logging rule
- Empty `tools` list (must have at least one pattern)
- Invalid window format (must be `<number>[s|m|h]`)
- Using `args_match: {command: ["echo"]}` instead of `command_allowlist: [echo]` — substring matching allows bypasses like `env AVAKILL_POLICY=/dev/null echo bypassed`
- Omitting `shell_safe: true` on shell allow rules — allows metacharacter injection (`echo hello | sh`)

### Output

Output ONLY the YAML policy. No explanations, no markdown fences. Start with `version: "1.0"`.
````

---

## After Generating

Validate the generated policy:

```bash
avakill validate policy.yaml
```

## Programmatic Access

You can also access the schema and prompt from Python:

```python
from avakill import get_json_schema, generate_prompt

# Get the JSON Schema (for structured output APIs)
schema = get_json_schema()

# Generate a customized LLM prompt
prompt = generate_prompt(
    tools_list=["file_read", "shell_exec", "db_query"],
    use_case="code assistant"
)
```
