"""AgentGuard exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.models import Decision


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""


class PolicyViolation(AgentGuardError):
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
    ) -> None:
        self.tool_name = tool_name
        self.decision = decision
        self.message = message or decision.reason or "Policy violation"
        super().__init__(str(self))

    def __str__(self) -> str:
        parts = [f"AgentGuard blocked '{self.tool_name}': {self.message}"]
        if self.decision.policy_name:
            parts.append(f"[policy: {self.decision.policy_name}]")
        return " ".join(parts)


class ConfigError(AgentGuardError):
    """Raised for invalid YAML configuration or policy files."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class RateLimitExceeded(PolicyViolation):
    """Raised when a tool call exceeds its configured rate limit."""
