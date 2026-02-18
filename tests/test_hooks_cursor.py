"""Tests for the Cursor hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.cursor import CursorAdapter


class TestCursorParseStdin:
    """Test parsing Cursor hook payloads."""

    def setup_method(self) -> None:
        self.adapter = CursorAdapter()

    def test_parse_before_shell_execution(self) -> None:
        raw = json.dumps({
            "conversation_id": "conv-1",
            "generation_id": "gen-1",
            "command": "git status",
            "cwd": "/home/user/project",
            "hook_event_name": "beforeShellExecution",
            "workspace_roots": ["/home/user/project"],
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "shell_command"
        assert req.args["command"] == "git status"
        assert req.args["cwd"] == "/home/user/project"
        assert req.agent == "cursor"

    def test_parse_before_mcp_execution(self) -> None:
        raw = json.dumps({
            "conversation_id": "conv-2",
            "generation_id": "gen-2",
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "github__create_issue",
            "tool_input": {"title": "Bug", "body": "Description"},
            "workspace_roots": ["/home/user/project"],
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "github__create_issue"
        assert req.args["title"] == "Bug"

    def test_parse_includes_workspace_roots(self) -> None:
        raw = json.dumps({
            "conversation_id": "conv-3",
            "generation_id": "gen-3",
            "command": "ls",
            "cwd": "",
            "hook_event_name": "beforeShellExecution",
            "workspace_roots": ["/a", "/b"],
        })
        req = self.adapter.parse_stdin(raw)
        assert req.context["workspace_roots"] == ["/a", "/b"]

    def test_parse_before_read_file(self) -> None:
        raw = json.dumps({
            "conversation_id": "conv-4",
            "generation_id": "gen-4",
            "hook_event_name": "beforeReadFile",
            "file_path": "/etc/passwd",
            "workspace_roots": [],
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "read_file"
        assert req.args["file_path"] == "/etc/passwd"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("not-json")


class TestCursorFormatResponse:
    """Test formatting responses for Cursor."""

    def setup_method(self) -> None:
        self.adapter = CursorAdapter()

    def test_deny_has_permission_deny(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["permission"] == "deny"
        assert parsed["continue"] is True

    def test_deny_has_agent_message(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="dangerous", policy="safety")
        stdout, _ = self.adapter.format_response(resp)
        parsed = json.loads(stdout)  # type: ignore[arg-type]
        assert "dangerous" in parsed["agentMessage"]
        assert "safety" in parsed["agentMessage"]

    def test_allow_has_permission_allow(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["permission"] == "allow"
        assert parsed["continue"] is True

    def test_always_exit_0(self) -> None:
        """Cursor uses JSON, not exit codes — always exit 0."""
        for decision in ("allow", "deny", "require_approval"):
            resp = EvaluateResponse(decision=decision, reason="test")  # type: ignore[arg-type]
            _, exit_code = self.adapter.format_response(resp)
            assert exit_code == 0, f"expected exit 0 for {decision}"

    def test_require_approval_returns_ask(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        stdout, _ = self.adapter.format_response(resp)
        parsed = json.loads(stdout)  # type: ignore[arg-type]
        assert parsed["permission"] == "ask"
