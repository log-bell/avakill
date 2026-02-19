"""Tests for the Gemini CLI hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.gemini_cli import GeminiCLIAdapter


class TestGeminiCLIParseStdin:
    """Test parsing Gemini CLI BeforeTool payloads."""

    def setup_method(self) -> None:
        self.adapter = GeminiCLIAdapter()

    def test_parse_run_shell_command(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": "ls -la"},
                "tool_use_id": "tu1",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "run_shell_command"
        assert req.args == {"command": "ls -la"}
        assert req.agent == "gemini-cli"

    def test_parse_read_file(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "BeforeTool",
                "tool_name": "read_file",
                "tool_input": {"file_path": "/etc/passwd"},
                "tool_use_id": "tu2",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "read_file"

    def test_parse_write_file(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "BeforeTool",
                "tool_name": "write_file",
                "tool_input": {"file_path": "/tmp/out.txt", "content": "hello"},
                "tool_use_id": "tu3",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "write_file"
        assert req.args["file_path"] == "/tmp/out.txt"

    def test_parse_edit_file(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "BeforeTool",
                "tool_name": "edit_file",
                "tool_input": {"file_path": "/tmp/f.py", "old": "a", "new": "b"},
                "tool_use_id": "tu4",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "edit_file"

    def test_parse_preserves_session_id(self) -> None:
        raw = json.dumps(
            {
                "session_id": "gemini-sess-42",
                "hook_event_name": "BeforeTool",
                "tool_name": "read_file",
                "tool_input": {},
                "tool_use_id": "tu5",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "gemini-sess-42"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("{bad json")


class TestGeminiCLIFormatResponse:
    """Test formatting responses for Gemini CLI."""

    def setup_method(self) -> None:
        self.adapter = GeminiCLIAdapter()

    def test_deny_json_format(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked", policy="safety")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["hookSpecificOutput"]["hookEventName"] == "BeforeTool"
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "blocked" in parsed["hookSpecificOutput"]["reason"]
        assert exit_code == 0

    def test_allow_returns_none(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 0

    def test_require_approval_returns_ask(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert exit_code == 0
