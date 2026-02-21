"""Wire protocol models for the AvaKill daemon.

Defines the JSON request/response contract between hook scripts (clients)
and the persistent daemon server.  Messages are newline-delimited JSON
over a Unix domain socket.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError


class EvaluateRequest(BaseModel):
    """Inbound evaluation request from a hook script or CLI client.

    Attributes:
        version: Protocol version (currently 1).
        agent: Agent identifier (e.g. "claude-code", "gemini-cli", "cli").
        event: Hook event type (e.g. "pre_tool_use").
        tool: Agent-native tool name before normalization.
        args: Tool arguments as a flat dict.
        context: Agent-specific metadata (cwd, session info, etc.).
    """

    version: int = Field(default=1, description="Protocol version.")
    agent: str = Field(description="Agent identifier.")
    event: str = Field(
        default="pre_tool_use",
        description="Hook event type.",
    )
    tool: str = Field(description="Tool name (agent-native).")
    args: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    """Outbound decision returned to the hook script.

    Attributes:
        decision: Allow, deny, or require human approval.
        reason: Human-readable explanation (present on deny).
        policy: Name of the matching policy rule, if any.
        latency_ms: Server-side evaluation time in milliseconds.
        modified_args: Rewritten tool arguments (future use).
    """

    decision: Literal["allow", "deny", "require_approval"]
    reason: str | None = None
    policy: str | None = None
    latency_ms: float = 0.0
    modified_args: dict[str, Any] | None = None
    approval_request_id: str | None = None


# ---------------------------------------------------------------------------
# Serialization helpers — newline-delimited JSON
# ---------------------------------------------------------------------------


def serialize_request(req: EvaluateRequest) -> bytes:
    """Serialize a request as newline-terminated JSON bytes."""
    return (req.model_dump_json() + "\n").encode("utf-8")


def serialize_response(resp: EvaluateResponse) -> bytes:
    """Serialize a response as newline-terminated JSON bytes."""
    return (resp.model_dump_json(exclude_none=True) + "\n").encode("utf-8")


def deserialize_request(data: bytes) -> EvaluateRequest:
    """Parse a request from raw bytes.

    Raises:
        ValueError: If *data* is not valid JSON or fails schema validation.
    """
    try:
        return EvaluateRequest.model_validate_json(data.strip())
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"invalid request: {exc}") from exc


def deserialize_response(data: bytes) -> EvaluateResponse:
    """Parse a response from raw bytes.

    Raises:
        ValueError: If *data* is not valid JSON or fails schema validation.
    """
    try:
        return EvaluateResponse.model_validate_json(data.strip())
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"invalid response: {exc}") from exc
