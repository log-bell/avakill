"""Recovery hints for fail-closed denials.

Maps denial decisions to structured, actionable recovery guidance.
"""

from __future__ import annotations

import re as _re_mod
from typing import Literal

_re_search = _re_mod.search

from pydantic import BaseModel, ConfigDict  # noqa: E402

RecoverySource = Literal[
    "self-protection-policy-write",
    "self-protection-uninstall",
    "self-protection-approve",
    "self-protection-source-mod",
    "policy-rule-deny",
    "rate-limit-exceeded",
    "integrity-last-known-good",
    "integrity-deny-all",
    "default-deny",
]

HintType = Literal["add_rule", "wait_rate_limit", "request_approval", "override", "blocked"]


class RecoveryHint(BaseModel):
    """Structured recovery guidance attached to a denial."""

    model_config = ConfigDict(frozen=True)

    source: RecoverySource
    summary: str
    steps: tuple[str, ...]
    doc_url: str | None = None

    # Structured recovery fields
    hint_type: HintType = "blocked"
    commands: tuple[str, ...] = ()
    yaml_snippet: str | None = None
    wait_seconds: int | None = None


def recovery_hint_for(
    decision: object,
    *,
    policy_status: str | None = None,
    tool_name: str | None = None,
) -> RecoveryHint | None:
    """Derive a RecoveryHint from a Decision's fields.

    Pure function — no I/O, no imports of mutable state.

    Args:
        decision: A ``Decision`` (or any object with ``.allowed``,
            ``.policy_name``, and ``.reason`` attributes).
        policy_status: The current integrity status of the guard
            (e.g. ``"last-known-good"``, ``"deny-all"``).

    Returns:
        A ``RecoveryHint`` if the decision is a denial, or ``None``
        for allowed decisions.
    """
    allowed = getattr(decision, "allowed", True)
    if allowed:
        return None

    policy_name: str = getattr(decision, "policy_name", None) or ""
    reason: str = getattr(decision, "reason", None) or ""
    reason_lower = reason.lower()

    # --- Require approval ---
    action: str = getattr(decision, "action", "deny")
    if action == "require_approval":
        return RecoveryHint(
            source="policy-rule-deny",
            summary=f"Requires human approval ({policy_name or 'unknown'})",
            steps=("Run avakill approve to approve this request.",),
            hint_type="request_approval",
            commands=("avakill approve",),
        )

    # --- Self-protection variants ---
    if policy_name == "self-protection":
        if (
            "targeting policy file" in reason_lower
            or "shell command targeting policy" in reason_lower
        ):
            return RecoveryHint(
                source="self-protection-policy-write",
                summary="Blocked policy file modification",
                steps=(
                    "Stage changes via a .proposed.yaml file.",
                    "Have a human run: avakill approve <proposed-file>",
                ),
                hint_type="blocked",
            )
        if "uninstall" in reason_lower:
            return RecoveryHint(
                source="self-protection-uninstall",
                summary="Blocked package uninstall",
                steps=(
                    "A human administrator must uninstall avakill manually.",
                    "Agents cannot remove their own guardrails.",
                ),
                hint_type="blocked",
            )
        if "approve" in reason_lower:
            return RecoveryHint(
                source="self-protection-approve",
                summary="Blocked approve command",
                steps=(
                    "Only humans may run: avakill approve",
                    "Agents cannot activate policy changes.",
                ),
                hint_type="blocked",
            )
        if "source file" in reason_lower:
            return RecoveryHint(
                source="self-protection-source-mod",
                summary="Blocked source modification",
                steps=(
                    "A human administrator must modify avakill source.",
                    "Agents cannot alter their own code.",
                ),
                hint_type="blocked",
            )
        # Fallback for unknown self-protection sub-variants
        return RecoveryHint(
            source="self-protection-source-mod",
            summary="Blocked by self-protection",
            steps=("A human administrator action is required.",),
            hint_type="blocked",
        )

    # --- Rate limit ---
    if "rate limit" in reason_lower:
        tool = tool_name or "<tool>"
        rate_yaml = (
            f"# Increase the rate limit for rule '{policy_name}':\n"
            f"- name: {policy_name or '<rule-name>'}\n"
            f'  tools: ["{tool}"]\n'
            f"  action: allow\n"
            f"  rate_limit:\n"
            f"    max_calls: 20\n"
            f'    window: "60s"'
        )
        # Try to parse the window seconds from the reason string.
        wait: int | None = None
        _m = _re_search(r"(\d+)\s*calls?\s+per\s+(\d+)s", reason)
        if _m:
            wait = int(_m.group(2))
        return RecoveryHint(
            source="rate-limit-exceeded",
            summary=f"Rate limit exceeded ({policy_name or 'unknown rule'})",
            steps=(
                "Wait for the current rate-limit window to expire.",
                "Adjust the rate_limit config in the matching policy rule.",
            ),
            hint_type="wait_rate_limit",
            yaml_snippet=rate_yaml,
            wait_seconds=wait,
        )

    # --- Integrity fallback states ---
    if policy_status == "last-known-good":
        return RecoveryHint(
            source="integrity-last-known-good",
            summary="Using cached last-known-good policy",
            steps=(
                "Re-sign the policy: avakill sign <policy-file>",
                "Verify the signature: avakill verify <policy-file>",
            ),
            hint_type="blocked",
            commands=(
                "avakill sign <policy-file>",
                "avakill verify <policy-file>",
            ),
        )
    if policy_status == "deny-all":
        return RecoveryHint(
            source="integrity-deny-all",
            summary="No fallback policy available — DENY ALL",
            steps=(
                "Restore the policy file from a known-good backup.",
                "Re-sign: avakill sign <policy-file>",
                "Restart the application.",
            ),
            hint_type="blocked",
        )

    # --- Default deny (no matching rule) ---
    if "default action" in reason_lower:
        tool = tool_name or "<tool>"
        default_yaml = (
            "# Add this rule to your avakill.yaml (above existing deny rules):\n"
            f"- name: allow-{tool}\n"
            f'  tools: ["{tool}"]\n'
            "  action: allow"
        )
        return RecoveryHint(
            source="default-deny",
            summary="No matching policy rule",
            steps=(
                "Add an explicit allow rule for this tool.",
                "Or set default_action: allow in the policy.",
                "Review current rules: avakill review <policy-file>",
            ),
            hint_type="add_rule",
            commands=("avakill review",),
            yaml_snippet=default_yaml,
        )

    # --- Overridable soft deny ---
    # NOTE: checked after rate-limit and default-deny because those
    # carry their own specific recovery semantics (wait / add rule).
    overridable: bool = getattr(decision, "overridable", False)
    if overridable and policy_name:
        tool = tool_name or "<tool>"
        return RecoveryHint(
            source="policy-rule-deny",
            summary=f"Soft-denied by rule '{policy_name}' (overridable)",
            steps=(f"Re-run with override: avakill evaluate --override --tool {tool}",),
            hint_type="override",
            commands=(f"avakill evaluate --override --tool {tool}",),
        )

    # --- Named policy rule deny ---
    if policy_name:
        standard_reason = f"Matched rule '{policy_name}'"
        tool = tool_name or "<tool>"

        if reason.strip() != standard_reason:
            # Custom message = intentional denial. Don't suggest blanket allow.
            rule_yaml = (
                f"# WARNING: Rule '{policy_name}' denied this call intentionally.\n"
                f"# Reason: {reason}\n"
                f"# If this was a mistake, add a targeted allow rule:\n"
                f"- name: allow-{tool}\n"
                f'  tools: ["{tool}"]\n'
                f"  action: allow\n"
                f"  conditions:\n"
                f"    args_not_match:  # adjust to your needs\n"
                f'      command: ["rm -rf", "sudo"]'
            )
        else:
            rule_yaml = (
                f"# Add this rule to your avakill.yaml (above '{policy_name}'):\n"
                f"- name: allow-{tool}\n"
                f'  tools: ["{tool}"]\n'
                f"  action: allow"
            )
        return RecoveryHint(
            source="policy-rule-deny",
            summary=f"Denied by rule '{policy_name}'",
            steps=(
                f"Review rule '{policy_name}' in your policy file.",
                "Add an allow rule above it if this tool should be permitted.",
                "Run: avakill review <policy-file>",
            ),
            hint_type="add_rule",
            commands=("avakill review",),
            yaml_snippet=rule_yaml,
        )

    return None
