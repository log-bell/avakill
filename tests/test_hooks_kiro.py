"""Tests for the Kiro CLI hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.kiro import KiroAdapter


class TestKiroParseStdin:
    """Test parsing Kiro CLI PreToolUse payloads."""

    def setup_method(self) -> None:
        self.adapter = KiroAdapter()

    def test_parse_execute_bash(self) -> None:
        raw = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/tmp",
                "tool_name": "execute_bash",
                "tool_input": {"command": "ls -la"},
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "execute_bash"
        assert req.args == {"command": "ls -la"}
        assert req.agent == "kiro"
        assert req.event == "PreToolUse"

    def test_parse_fs_write(self) -> None:
        raw = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/home/user",
                "tool_name": "fs_write",
                "tool_input": {"path": "/tmp/out.txt", "content": "hello"},
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "fs_write"
        assert req.args["path"] == "/tmp/out.txt"

    def test_parse_fs_read(self) -> None:
        raw = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "fs_read",
                "tool_input": {"path": "/etc/passwd"},
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "fs_read"

    def test_parse_preserves_cwd(self) -> None:
        raw = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/projects/myapp",
                "tool_name": "execute_bash",
                "tool_input": {},
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["cwd"] == "/projects/myapp"

    def test_parse_missing_cwd_omitted_from_context(self) -> None:
        raw = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "execute_bash",
                "tool_input": {},
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert "cwd" not in req.context

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("{bad json")

    def test_parse_missing_tool_name_raises(self) -> None:
        with pytest.raises(KeyError):
            self.adapter.parse_stdin(json.dumps({"hook_event_name": "PreToolUse"}))


class TestKiroFormatResponse:
    """Test formatting responses for Kiro CLI."""

    def setup_method(self) -> None:
        self.adapter = KiroAdapter()

    def test_deny_exit_code_2(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked", policy="safety")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 2

    def test_deny_reason_on_stderr(self, capsys: pytest.CaptureFixture) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked", policy="safety")
        self.adapter.format_response(resp)
        captured = capsys.readouterr()
        assert "blocked" in captured.err
        assert "[safety]" in captured.err

    def test_deny_self_protection_no_policy_suffix(self, capsys: pytest.CaptureFixture) -> None:
        resp = EvaluateResponse(
            decision="deny", reason="Self-protection: blocked", policy="self-protection"
        )
        self.adapter.format_response(resp)
        captured = capsys.readouterr()
        assert "Self-protection: blocked" in captured.err
        assert "[self-protection]" not in captured.err

    def test_allow_returns_none(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 0

    def test_require_approval_exits_2(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 2  # Kiro has no "ask" — blocks instead

    def test_require_approval_stderr_message(self, capsys: pytest.CaptureFixture) -> None:
        resp = EvaluateResponse(decision="require_approval")
        self.adapter.format_response(resp)
        captured = capsys.readouterr()
        assert "requires approval" in captured.err
