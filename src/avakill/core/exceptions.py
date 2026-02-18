"""AvaKill exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avakill.core.models import Decision


class AvaKillError(Exception):
    """Base exception for all AvaKill errors."""


class PolicyViolation(AvaKillError):
    """Raised when a tool call is denied by policy.

    Attributes:
        tool_name: The name of the tool that was blocked.
        decision: The Decision object that caused the violation.
        message: A human-readable explanation of the violation.
    """

    def __init__(
        self,
        tool_name: str,
        decision: Decision,
        message: str | None = None,
        recovery_hint: object | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.decision = decision
        self.message = message or decision.reason or "Policy violation"
        self.recovery_hint = recovery_hint
        super().__init__(str(self))

    def __str__(self) -> str:
        parts = [f"AvaKill blocked '{self.tool_name}': {self.message}"]
        if self.decision.policy_name:
            parts.append(f"[policy: {self.decision.policy_name}]")
        if self.recovery_hint is not None:
            summary = getattr(self.recovery_hint, "summary", None)
            if summary:
                parts.append(f"[recovery: {summary}]")
        return " ".join(parts)


class ConfigError(AvaKillError):
    """Raised for invalid YAML configuration or policy files."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class RateLimitExceeded(PolicyViolation):
    """Raised when a tool call exceeds its configured rate limit."""
