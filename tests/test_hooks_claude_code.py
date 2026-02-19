"""Tests for the Claude Code hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.claude_code import ClaudeCodeAdapter


class TestClaudeCodeParseStdin:
    """Test parsing Claude Code PreToolUse payloads."""

    def setup_method(self) -> None:
        self.adapter = ClaudeCodeAdapter()

    def test_parse_bash_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls -la"},
                "tool_use_id": "tu1",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "Bash"
        assert req.args == {"command": "ls -la"}
        assert req.agent == "claude-code"

    def test_parse_write_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": "/tmp/test.py", "content": "print('hi')"},
                "tool_use_id": "tu2",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "Write"
        assert req.args["file_path"] == "/tmp/test.py"

    def test_parse_edit_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": "/tmp/test.py",
                    "old_string": "foo",
                    "new_string": "bar",
                },
                "tool_use_id": "tu3",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "Edit"
        assert req.args["old_string"] == "foo"

    def test_parse_read_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "/etc/passwd"},
                "tool_use_id": "tu4",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "Read"

    def test_parse_web_fetch_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://example.com"},
                "tool_use_id": "tu5",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "WebFetch"

    def test_parse_mcp_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__memory__store",
                "tool_input": {"key": "value"},
                "tool_use_id": "tu6",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "mcp__memory__store"

    def test_parse_preserves_session_id(self) -> None:
        raw = json.dumps(
            {
                "session_id": "abc-123",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hi"},
                "tool_use_id": "tu7",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "abc-123"

    def test_parse_preserves_cwd_in_context(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
                "cwd": "/home/user/project",
                "tool_use_id": "tu8",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["cwd"] == "/home/user/project"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("not json{{{")


class TestClaudeCodeFormatResponse:
    """Test formatting responses for Claude Code."""

    def setup_method(self) -> None:
        self.adapter = ClaudeCodeAdapter()

    def test_deny_returns_hook_specific_output_json(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        stdout, _ = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert "hookSpecificOutput" in parsed

    def test_deny_has_permission_decision_deny(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        stdout, _ = self.adapter.format_response(resp)
        parsed = json.loads(stdout)  # type: ignore[arg-type]
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_deny_includes_reason(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="dangerous command", policy="safety")
        stdout, _ = self.adapter.format_response(resp)
        parsed = json.loads(stdout)  # type: ignore[arg-type]
        reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        assert "dangerous command" in reason
        assert "safety" in reason

    def test_allow_returns_none_stdout(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, _ = self.adapter.format_response(resp)
        assert stdout is None

    def test_allow_exit_code_is_0(self) -> None:
        resp = EvaluateResponse(decision="allow")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 0

    def test_deny_exit_code_is_0(self) -> None:
        """Claude Code uses JSON deny, not exit code 2."""
        resp = EvaluateResponse(decision="deny", reason="blocked")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 0

    def test_require_approval_returns_ask(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert exit_code == 0
