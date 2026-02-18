"""Recovery hints for fail-closed denials.

Maps denial decisions to structured, actionable recovery guidance.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

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


class RecoveryHint(BaseModel):
    """Structured recovery guidance attached to a denial."""

    model_config = ConfigDict(frozen=True)

    source: RecoverySource
    summary: str
    steps: tuple[str, ...]
    doc_url: str | None = None


def recovery_hint_for(
    decision: object,
    *,
    policy_status: str | None = None,
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

    # --- Self-protection variants ---
    if policy_name == "self-protection":
        if "targeting policy file" in reason_lower or "shell command targeting policy" in reason_lower:
            return RecoveryHint(
                source="self-protection-policy-write",
                summary="Blocked policy file modification",
                steps=(
                    "Stage changes via a .proposed.yaml file.",
                    "Have a human run: avakill approve <proposed-file>",
                ),
            )
        if "uninstall" in reason_lower:
            return RecoveryHint(
                source="self-protection-uninstall",
                summary="Blocked package uninstall",
                steps=(
                    "A human administrator must uninstall avakill manually.",
                    "Agents cannot remove their own guardrails.",
                ),
            )
        if "approve" in reason_lower:
            return RecoveryHint(
                source="self-protection-approve",
                summary="Blocked approve command",
                steps=(
                    "Only humans may run: avakill approve",
                    "Agents cannot activate policy changes.",
                ),
            )
        if "source file" in reason_lower:
            return RecoveryHint(
                source="self-protection-source-mod",
                summary="Blocked source modification",
                steps=(
                    "A human administrator must modify avakill source.",
                    "Agents cannot alter their own code.",
                ),
            )
        # Fallback for unknown self-protection sub-variants
        return RecoveryHint(
            source="self-protection-source-mod",
            summary="Blocked by self-protection",
            steps=("A human administrator action is required.",),
        )

    # --- Rate limit ---
    if "rate limit" in reason_lower:
        return RecoveryHint(
            source="rate-limit-exceeded",
            summary=f"Rate limit exceeded ({policy_name or 'unknown rule'})",
            steps=(
                "Wait for the current rate-limit window to expire.",
                "Adjust the rate_limit config in the matching policy rule.",
            ),
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
        )

    # --- Default deny (no matching rule) ---
    if "default action" in reason_lower:
        return RecoveryHint(
            source="default-deny",
            summary="No matching policy rule",
            steps=(
                "Add an explicit allow rule for this tool.",
                "Or set default_action: allow in the policy.",
                "Review current rules: avakill review <policy-file>",
            ),
        )

    # --- Named policy rule deny ---
    if policy_name:
        return RecoveryHint(
            source="policy-rule-deny",
            summary=f"Denied by rule '{policy_name}'",
            steps=(
                f"Review rule '{policy_name}' in your policy file.",
                "Add an allow rule above it if this tool should be permitted.",
                "Run: avakill review <policy-file>",
            ),
        )

    return None
