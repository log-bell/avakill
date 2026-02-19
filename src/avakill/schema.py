"""JSON Schema export and LLM prompt generation for AvaKill policies.

Provides functions to export the PolicyConfig JSON Schema and generate
self-contained prompts that any LLM can use to write valid policies.
"""

from __future__ import annotations

import json
from pathlib import Path

from avakill.core.models import PolicyConfig

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_EVALUATION_RULES = """\
## Evaluation Rules

1. **First-match-wins**: Rules are evaluated top-to-bottom. The first rule whose \
`tools` pattern matches the tool call is applied. No further rules are checked.
2. **Glob syntax**: Tool patterns use glob matching — `*` matches any sequence of \
characters. Examples: `shell_*` matches `shell_execute`, `shell_run`; `*_read` matches \
`file_read`, `db_read`; `*` or `all` matches every tool.
3. **Case-insensitive matching**: `args_match` and `args_not_match` perform \
case-insensitive substring matching against stringified argument values.
4. **default_action**: If no rule matches a tool call, the `default_action` is applied. \
Use `deny` for an allowlist approach (safer), `allow` for audit/permissive mode.
5. **Rate limiting**: `rate_limit` uses a sliding window. The `window` field is a \
duration string like `60s`, `5m`, or `1h`.
6. **Order matters**: Place specific deny rules (e.g. blocking destructive SQL) \
*before* broader allow rules for the same tools. Otherwise the allow rule matches first \
and the deny rule never fires."""

_ANTI_PATTERNS = """\
## Common Mistakes to Avoid

1. **Putting a broad allow rule before a specific deny rule** — the allow matches first \
and the deny never fires. Always put deny/block rules above allow rules for the same tools.
2. **Using `default_action: allow` without a catch-all log rule** — tool calls that \
match no rule silently pass through with no audit trail. Add a final `all` rule with \
`log: true`.
3. **Forgetting that `args_match` is substring-based** — matching `"DELETE"` will also \
match `"UNDELETE"`. Be specific with your patterns.
4. **Empty `tools` list** — every rule must have at least one tool pattern.
5. **Invalid `window` format** — must be a number followed by `s`, `m`, or `h` \
(e.g. `60s`, `5m`, `1h`). No spaces, no other units.
6. **Missing `version: "1.0"`** — the version field is required and must be exactly `"1.0"`.
7. **Using `require_approval` without a human-in-the-loop system** — this action pauses \
execution for human review. Only use it if your integration supports approval workflows."""

_SELF_PROTECTION = """\
## Self-Protection (Hardcoded)

AvaKill includes hardcoded self-protection rules that run **before** user-defined \
policies and **cannot be overridden**. These prevent agents from weakening their own \
guardrails.

**What is protected:**
- **Policy file** (`avakill.yaml` / `avakill.yml`): Cannot be written, deleted, moved, \
or modified by agents.
- **AvaKill package**: Cannot be uninstalled via pip, uv, or poetry.
- **Approve command**: `avakill approve` can only be run by humans, not agents.
- **Source files**: `src/avakill/` and `site-packages/avakill/` are protected from writes.

**Policy staging workflow:**
1. Write proposed changes to a `.proposed.yaml` file (e.g. `avakill.proposed.yaml`) — \
this is allowed.
2. A human reviews the proposal: `avakill review avakill.proposed.yaml`
3. A human activates it: `avakill approve avakill.proposed.yaml`

**Never write directly to `avakill.yaml`.** Always use the staging workflow above."""


def get_json_schema() -> dict:
    """Return the JSON Schema for PolicyConfig as a dictionary.

    This is the canonical schema derived from the Pydantic models.
    Useful for structured output APIs, IDE extensions, and validators.
    """
    return PolicyConfig.model_json_schema()


def get_json_schema_string(*, compact: bool = False) -> str:
    """Return the JSON Schema for PolicyConfig as a JSON string.

    Args:
        compact: If True, return minified JSON. Otherwise pretty-printed.
    """
    schema = get_json_schema()
    if compact:
        return json.dumps(schema, separators=(",", ":"))
    return json.dumps(schema, indent=2)


def _load_template(name: str) -> str:
    """Load a template YAML file by name."""
    path = _TEMPLATES_DIR / f"{name}.yaml"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def generate_prompt(
    *,
    tools_list: list[str] | None = None,
    use_case: str | None = None,
) -> str:
    """Generate a self-contained LLM prompt for writing AvaKill policies.

    The prompt includes the JSON Schema, evaluation rules, anti-patterns,
    and annotated examples. Any LLM can use this prompt to produce a valid
    YAML policy file.

    Args:
        tools_list: Optional list of actual tool names available in the user's
            system. When provided, the prompt instructs the LLM to write rules
            targeting these specific tools.
        use_case: Optional description of the user's use case (e.g. "code
            assistant", "data pipeline agent"). Helps the LLM tailor the policy.
    """
    schema_json = get_json_schema_string()

    sections: list[str] = []

    # Header
    sections.append(
        "# AvaKill Policy Generation Prompt\n\n"
        "You are generating a YAML policy file for AvaKill, an open-source safety "
        "firewall for AI agents. The policy defines rules that intercept and evaluate "
        "tool calls before they execute. AvaKill enforces these rules deterministically "
        "— no LLM is involved at runtime.\n\n"
        "Your output must be a single valid YAML document that conforms to the JSON "
        "Schema below."
    )

    # User context
    if use_case or tools_list:
        context_parts: list[str] = ["## Context"]
        if use_case:
            context_parts.append(f"\n**Use case:** {use_case}")
        if tools_list:
            context_parts.append(
                f"\n**Available tools:** {', '.join(tools_list)}\n\n"
                "Write rules that reference these specific tool names. You may also "
                "use glob patterns to group them (e.g. `db_*` for all database tools)."
            )
        sections.append("\n".join(context_parts))

    # JSON Schema
    sections.append(
        f"## JSON Schema\n\n"
        f"The policy file must conform to this schema:\n\n"
        f"```json\n{schema_json}\n```"
    )

    # Evaluation rules
    sections.append(_EVALUATION_RULES)

    # Anti-patterns
    sections.append(_ANTI_PATTERNS)

    # Self-protection documentation
    sections.append(_SELF_PROTECTION)

    # Examples from templates
    examples_section: list[str] = ["## Examples"]

    default_yaml = _load_template("default")
    if default_yaml:
        examples_section.append(
            "\n### Example 1: Default (balanced security)\n\n"
            "Allows reads, blocks destructive operations, rate-limits searches. "
            "Good starting point for most applications.\n\n"
            f"```yaml\n{default_yaml.rstrip()}\n```"
        )

    strict_yaml = _load_template("strict")
    if strict_yaml:
        examples_section.append(
            "\n### Example 2: Strict (maximum safety)\n\n"
            "Deny by default, explicit allowlist only. All writes and executions "
            "require human approval. Rate limits on everything.\n\n"
            f"```yaml\n{strict_yaml.rstrip()}\n```"
        )

    permissive_yaml = _load_template("permissive")
    if permissive_yaml:
        examples_section.append(
            "\n### Example 3: Permissive (audit mode)\n\n"
            "Allow by default, log everything. Only blocks catastrophic operations "
            "like `DROP DATABASE` or `rm -rf /`. Good for development and audit.\n\n"
            f"```yaml\n{permissive_yaml.rstrip()}\n```"
        )

    sections.append("\n".join(examples_section))

    # Output instructions
    sections.append(
        "## Output Instructions\n\n"
        "1. Output ONLY the YAML policy — no explanations, no markdown fences, "
        "no surrounding text.\n"
        '2. Start with `version: "1.0"` and `default_action:`.\n'
        "3. Order rules from most-specific deny rules to broader allow rules.\n"
        "4. Include a `message` field on deny and require_approval rules explaining why.\n"
        "5. Use comments (`#`) to document each rule's purpose.\n"
        "6. Validate that every `tools` list has at least one entry.\n"
        "7. Validate that every `window` value matches the pattern `<number>[s|m|h]`.\n"
        "8. Save the policy as a `.proposed.yaml` file (e.g. `avakill.proposed.yaml`), "
        "never write directly to `avakill.yaml`. A human will review and approve it."
    )

    return "\n\n".join(sections)
