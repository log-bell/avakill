"""Tests for the daemon wire protocol models and serialization."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_request,
    deserialize_response,
    serialize_request,
    serialize_response,
)


class TestEvaluateRequest:
    """EvaluateRequest model validation."""

    def test_minimal_request(self) -> None:
        req = EvaluateRequest(agent="cli", tool="file_read")
        assert req.agent == "cli"
        assert req.tool == "file_read"

    def test_full_request_with_all_fields(self) -> None:
        req = EvaluateRequest(
            version=1,
            agent="claude-code",
            event="pre_tool_use",
            tool="Bash",
            args={"command": "ls"},
            context={"cwd": "/tmp", "session_id": "abc"},
        )
        assert req.version == 1
        assert req.agent == "claude-code"
        assert req.event == "pre_tool_use"
        assert req.tool == "Bash"
        assert req.args == {"command": "ls"}
        assert req.context["cwd"] == "/tmp"

    def test_default_version_is_1(self) -> None:
        req = EvaluateRequest(agent="cli", tool="t")
        assert req.version == 1

    def test_default_event_is_pre_tool_use(self) -> None:
        req = EvaluateRequest(agent="cli", tool="t")
        assert req.event == "pre_tool_use"

    def test_missing_agent_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            EvaluateRequest(tool="t")  # type: ignore[call-arg]

    def test_missing_tool_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            EvaluateRequest(agent="cli")  # type: ignore[call-arg]

    def test_default_args_empty_dict(self) -> None:
        req = EvaluateRequest(agent="cli", tool="t")
        assert req.args == {}

    def test_default_context_empty_dict(self) -> None:
        req = EvaluateRequest(agent="cli", tool="t")
        assert req.context == {}


class TestEvaluateResponse:
    """EvaluateResponse model validation."""

    def test_allow_response(self) -> None:
        resp = EvaluateResponse(decision="allow")
        assert resp.decision == "allow"
        assert resp.reason is None
        assert resp.policy is None

    def test_deny_response_with_reason_and_policy(self) -> None:
        resp = EvaluateResponse(
            decision="deny",
            reason="blocked by policy",
            policy="block-destructive",
            latency_ms=0.42,
        )
        assert resp.decision == "deny"
        assert resp.reason == "blocked by policy"
        assert resp.policy == "block-destructive"
        assert resp.latency_ms == pytest.approx(0.42)

    def test_require_approval_response(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        assert resp.decision == "require_approval"

    def test_default_latency_is_zero(self) -> None:
        resp = EvaluateResponse(decision="allow")
        assert resp.latency_ms == 0.0

    def test_modified_args(self) -> None:
        resp = EvaluateResponse(
            decision="allow",
            modified_args={"command": "ls --dry-run"},
        )
        assert resp.modified_args == {"command": "ls --dry-run"}


class TestSerialization:
    """Serialization and deserialization helpers."""

    def test_serialize_response_newline_terminated(self) -> None:
        resp = EvaluateResponse(decision="allow")
        data = serialize_response(resp)
        assert data.endswith(b"\n")
        assert json.loads(data)["decision"] == "allow"

    def test_serialize_response_excludes_none_fields(self) -> None:
        resp = EvaluateResponse(decision="allow")
        data = serialize_response(resp)
        parsed = json.loads(data)
        assert "reason" not in parsed
        assert "policy" not in parsed
        assert "modified_args" not in parsed

    def test_serialize_request_newline_terminated(self) -> None:
        req = EvaluateRequest(agent="cli", tool="t")
        data = serialize_request(req)
        assert data.endswith(b"\n")
        assert json.loads(data)["agent"] == "cli"

    def test_deserialize_request_from_bytes(self) -> None:
        raw = b'{"agent": "claude-code", "tool": "Bash", "args": {"command": "ls"}}'
        req = deserialize_request(raw)
        assert req.agent == "claude-code"
        assert req.tool == "Bash"
        assert req.args["command"] == "ls"

    def test_deserialize_request_strips_whitespace(self) -> None:
        raw = b'  {"agent": "cli", "tool": "t"}  \n  '
        req = deserialize_request(raw)
        assert req.agent == "cli"

    def test_deserialize_invalid_json_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid request"):
            deserialize_request(b"not json at all")

    def test_deserialize_missing_required_field_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid request"):
            deserialize_request(b'{"agent": "cli"}')  # missing tool

    def test_deserialize_response_from_bytes(self) -> None:
        raw = b'{"decision": "deny", "reason": "blocked"}'
        resp = deserialize_response(raw)
        assert resp.decision == "deny"
        assert resp.reason == "blocked"

    def test_deserialize_response_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid response"):
            deserialize_response(b"garbage")

    def test_round_trip_request(self) -> None:
        original = EvaluateRequest(
            agent="gemini-cli",
            tool="run_shell_command",
            args={"command": "echo hello"},
            context={"cwd": "/home"},
        )
        data = serialize_request(original)
        restored = deserialize_request(data)
        assert restored.agent == original.agent
        assert restored.tool == original.tool
        assert restored.args == original.args
        assert restored.context == original.context

    def test_round_trip_response(self) -> None:
        original = EvaluateResponse(
            decision="deny",
            reason="dangerous",
            policy="safety",
            latency_ms=1.23,
        )
        data = serialize_response(original)
        restored = deserialize_response(data)
        assert restored.decision == original.decision
        assert restored.reason == original.reason
        assert restored.policy == original.policy
        assert restored.latency_ms == pytest.approx(original.latency_ms)
