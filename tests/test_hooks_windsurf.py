"""Tests for the Windsurf hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.windsurf import WindsurfAdapter


class TestWindsurfParseStdin:
    """Test parsing Windsurf Cascade Hooks payloads."""

    def setup_method(self) -> None:
        self.adapter = WindsurfAdapter()

    def test_parse_pre_run_command(self) -> None:
        raw = json.dumps({
            "agent_action_name": "pre_run_command",
            "trajectory_id": "traj-1",
            "execution_id": "exec-1",
            "timestamp": "2026-02-18T14:00:00Z",
            "tool_info": {
                "command_line": "rm -rf /important-data",
                "cwd": "/home/user/project",
            },
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "run_command"
        assert req.args["command"] == "rm -rf /important-data"
        assert req.args["cwd"] == "/home/user/project"
        assert req.agent == "windsurf"

    def test_parse_pre_write_code(self) -> None:
        raw = json.dumps({
            "agent_action_name": "pre_write_code",
            "trajectory_id": "traj-2",
            "execution_id": "exec-2",
            "timestamp": "2026-02-18T14:00:00Z",
            "tool_info": {
                "file_path": "/Users/user/project/config.py",
                "edits": [{"old_string": "DEBUG = False", "new_string": "DEBUG = True"}],
            },
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "write_code"
        assert req.args["file_path"] == "/Users/user/project/config.py"
        assert len(req.args["edits"]) == 1

    def test_parse_pre_read_code(self) -> None:
        raw = json.dumps({
            "agent_action_name": "pre_read_code",
            "trajectory_id": "traj-3",
            "execution_id": "exec-3",
            "timestamp": "2026-02-18T14:00:00Z",
            "tool_info": {"file_path": "/etc/passwd"},
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "read_code"
        assert req.args["file_path"] == "/etc/passwd"

    def test_parse_pre_mcp_tool_use(self) -> None:
        raw = json.dumps({
            "agent_action_name": "pre_mcp_tool_use",
            "trajectory_id": "traj-4",
            "execution_id": "exec-4",
            "timestamp": "2026-02-18T14:00:00Z",
            "tool_info": {
                "mcp_server_name": "github",
                "mcp_tool_name": "create_issue",
                "mcp_tool_arguments": {"title": "Bug", "body": "desc"},
            },
        })
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "mcp_tool"
        assert req.args["mcp_server_name"] == "github"
        assert req.args["mcp_tool_name"] == "create_issue"

    def test_parse_preserves_trajectory_id(self) -> None:
        raw = json.dumps({
            "agent_action_name": "pre_run_command",
            "trajectory_id": "my-traj",
            "execution_id": "my-exec",
            "timestamp": "2026-02-18T14:00:00Z",
            "tool_info": {"command_line": "echo hi"},
        })
        req = self.adapter.parse_stdin(raw)
        assert req.context["trajectory_id"] == "my-traj"
        assert req.context["execution_id"] == "my-exec"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("{bad")


class TestWindsurfFormatResponse:
    """Test formatting responses for Windsurf."""

    def setup_method(self) -> None:
        self.adapter = WindsurfAdapter()

    def test_deny_exit_code_is_2(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 2

    def test_deny_includes_reason_text(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="dangerous command", policy="safety")
        stdout, _ = self.adapter.format_response(resp)
        assert stdout is not None
        assert "dangerous command" in stdout
        assert "safety" in stdout

    def test_allow_exit_code_is_0(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 0

    def test_require_approval_exits_0(self) -> None:
        """Windsurf has no native 'ask' — treated as allow."""
        resp = EvaluateResponse(decision="require_approval")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 0
