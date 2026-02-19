"""Pydantic v2 data models for AvaKill policies, events, and decisions."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ToolCall(BaseModel):
    """Represents an intercepted tool call from an AI agent.

    Attributes:
        tool_name: The name of the tool being invoked.
        arguments: The arguments passed to the tool.
        agent_id: Optional identifier for the agent making the call.
        session_id: Optional session identifier for grouping related calls.
        timestamp: When the tool call was intercepted (defaults to now UTC).
        metadata: Arbitrary additional data attached to the call.
    """

    tool_name: str
    arguments: dict[str, Any]
    agent_id: str | None = None
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """The result of evaluating a tool call against a policy.

    Attributes:
        allowed: Whether the tool call is permitted.
        action: The action taken by the matching rule.
        policy_name: The name of the policy rule that matched, if any.
        reason: A human-readable explanation of the decision.
        timestamp: When the decision was made.
        latency_ms: How long the policy evaluation took in milliseconds.
    """

    model_config = ConfigDict(frozen=True)

    allowed: bool
    action: Literal["allow", "deny", "require_approval"]
    policy_name: str | None = None
    reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: float = 0.0
    overridable: bool = False


class AuditEvent(BaseModel):
    """A complete audit log record linking a tool call to its decision.

    Attributes:
        id: Unique identifier for the event (auto-generated UUID4).
        tool_call: The intercepted tool call.
        decision: The policy decision for this call.
        execution_result: The result of the tool execution, if it was allowed.
        error: Error message if the tool execution failed.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    tool_call: ToolCall
    decision: Decision
    execution_result: Any | None = None
    error: str | None = None
    recovery_hint: Any | None = None


class RuleConditions(BaseModel):
    """Conditions for matching tool call arguments against a policy rule.

    Attributes:
        args_match: Argument values must contain one of these strings (case-insensitive).
        args_not_match: Deny if argument values contain any of these strings (case-insensitive).
        shell_safe: When True, reject commands containing shell metacharacters.
    """

    args_match: dict[str, list[str]] | None = None
    args_not_match: dict[str, list[str]] | None = None
    shell_safe: bool = False


_WINDOW_PATTERN = re.compile(r"^\d+[smh]$")
_WINDOW_MULTIPLIERS = {"s": 1, "m": 60, "h": 3600}


class RateLimit(BaseModel):
    """Rate limiting configuration for a policy rule.

    Attributes:
        max_calls: Maximum number of calls allowed within the window.
        window: Time window as a string (e.g. "60s", "5m", "1h").
    """

    max_calls: int = Field(description="Maximum number of calls allowed within the window.")
    window: str = Field(
        description="Time window as a duration string: number + unit. "
        "Units: 's' (seconds), 'm' (minutes), 'h' (hours). Examples: '60s', '5m', '1h'.",
        pattern=r"^\d+[smh]$",
    )

    @field_validator("window")
    @classmethod
    def _validate_window(cls, v: str) -> str:
        if not _WINDOW_PATTERN.match(v):
            raise ValueError(
                f"Invalid window format '{v}': must match pattern '<number>[s|m|h]' "
                f"(e.g. '60s', '5m', '1h')"
            )
        return v

    def window_seconds(self) -> int:
        """Convert the window string to total seconds.

        Returns:
            The window duration in seconds.
        """
        unit = self.window[-1]
        value = int(self.window[:-1])
        return value * _WINDOW_MULTIPLIERS[unit]


class PolicyRule(BaseModel):
    """A single rule in the policy configuration.

    Attributes:
        name: Human-readable name for this rule.
        tools: List of tool-name patterns this rule applies to (supports globs).
        action: What to do when this rule matches.
        enforcement: Enforcement level for this rule.
        conditions: Optional conditions for matching tool call arguments.
        rate_limit: Optional rate limiting for this rule.
        message: Custom message to include in violations or audit logs.
        log: Whether to log matches against this rule.
    """

    name: str = Field(
        description="Human-readable name for this rule (e.g. 'block-destructive-sql').",
    )
    tools: list[str] = Field(
        description=(
            "List of tool-name patterns this rule applies to. "
            "Supports glob patterns: '*' matches everything, "
            "'shell_*' matches any tool starting with 'shell_', "
            "'*_read' matches any tool ending with '_read'. "
            "Use 'all' to match every tool."
        ),
        min_length=1,
    )
    action: Literal["allow", "deny", "require_approval"] = Field(
        description="Action to take when this rule matches. "
        "'allow' permits the call, 'deny' blocks it, 'require_approval' pauses for human review.",
    )
    enforcement: Literal["hard", "soft", "advisory"] = Field(
        default="hard",
        description="Enforcement level. "
        "'hard' cannot be overridden, "
        "'soft' is overridable with audit trail, "
        "'advisory' logs the match but always allows.",
    )
    conditions: RuleConditions | None = None
    rate_limit: RateLimit | None = None
    message: str | None = None
    log: bool = True

    @field_validator("tools")
    @classmethod
    def _tools_must_not_be_empty(cls, v: list[str]) -> list[str]:
        if len(v) == 0:
            raise ValueError("tools must have at least one entry")
        return v


class PolicyConfig(BaseModel):
    """Top-level parsed YAML policy configuration.

    Attributes:
        version: Schema version string (must be "1.0").
        default_action: Action to take when no rule matches.
        policies: Ordered list of policy rules evaluated top-to-bottom.
        notifications: Optional notification configuration.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "version": "1.0",
                    "default_action": "deny",
                    "policies": [
                        {
                            "name": "allow-reads",
                            "tools": ["*_read", "*_get", "*_list"],
                            "action": "allow",
                        },
                        {
                            "name": "block-destructive-sql",
                            "tools": ["database_*", "sql_*"],
                            "action": "deny",
                            "conditions": {"args_match": {"query": ["DROP", "DELETE", "TRUNCATE"]}},
                            "message": "Destructive SQL is blocked",
                        },
                        {
                            "name": "rate-limit-search",
                            "tools": ["web_search"],
                            "action": "allow",
                            "rate_limit": {"max_calls": 10, "window": "60s"},
                        },
                    ],
                }
            ]
        }
    )

    version: str = Field(default="1.0", description="Schema version string. Must be '1.0'.")
    default_action: Literal["allow", "deny"] = Field(
        default="deny",
        description="Action to take when no rule matches. "
        "'deny' is safer (allowlist approach), 'allow' is for audit/permissive mode.",
    )
    policies: list[PolicyRule] = Field(
        description="Ordered list of policy rules evaluated top-to-bottom. First match wins."
    )
    notifications: dict[str, Any] = Field(default_factory=dict)

    @field_validator("version")
    @classmethod
    def _version_must_be_1_0(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"Unsupported policy version '{v}': only '1.0' is supported")
        return v
