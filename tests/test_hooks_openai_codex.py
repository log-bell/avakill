"""Tests for the OpenAI Codex CLI hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.openai_codex import OpenAICodexAdapter


class TestOpenAICodexParseStdinNested:
    """Test parsing nested Codex HookPayload format."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_parse_shell_tool(self) -> None:
        """local_shell with command list is joined; workdir preserved."""
        raw = json.dumps(
            {
                "session_id": "sess-1",
                "cwd": "/home/user",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_abc",
                    "tool_name": "shell",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "local_shell",
                        "params": {
                            "command": ["rm", "-rf", "/"],
                            "workdir": "/tmp",
                        },
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "shell"
        assert req.args["command"] == "rm -rf /"
        assert req.args["workdir"] == "/tmp"
        assert req.agent == "openai-codex"

    def test_parse_apply_patch_tool(self) -> None:
        """custom input_type extracts the input field."""
        raw = json.dumps(
            {
                "session_id": "sess-2",
                "cwd": "/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_patch",
                    "tool_name": "apply_patch",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "custom",
                        "input": "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new",
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "apply_patch"
        assert "input" in req.args
        assert "old" in req.args["input"]

    def test_parse_mcp_tool(self) -> None:
        """mcp input_type extracts server, tool, and arguments."""
        raw = json.dumps(
            {
                "session_id": "sess-3",
                "cwd": "/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_mcp",
                    "tool_name": "mcp_call",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "mcp",
                        "server": "memory-server",
                        "tool": "store_memory",
                        "arguments": {"key": "value"},
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "mcp_call"
        assert req.args["mcp_server"] == "memory-server"
        assert req.args["mcp_tool"] == "store_memory"
        assert req.args["arguments"] == {"key": "value"}

    def test_parse_preserves_session_id(self) -> None:
        """session_id and cwd are preserved in context."""
        raw = json.dumps(
            {
                "session_id": "unique-session-42",
                "cwd": "/workspace/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "tool_name": "shell",
                    "tool_input": {
                        "input_type": "local_shell",
                        "params": {"command": ["echo", "hi"]},
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "unique-session-42"
        assert req.context["cwd"] == "/workspace/project"

    def test_parse_preserves_call_id(self) -> None:
        """call_id from hook_event is preserved in context."""
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_xyz_789",
                    "tool_name": "shell",
                    "tool_input": {
                        "input_type": "local_shell",
                        "params": {"command": ["ls"]},
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["call_id"] == "call_xyz_789"

    def test_parse_unknown_input_type_passes_through(self) -> None:
        """Unknown input_type passes through all fields except input_type."""
        raw = json.dumps(
            {
                "session_id": "s1",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "tool_name": "future_tool",
                    "tool_input": {
                        "input_type": "future_type",
                        "some_field": "some_value",
                        "other_field": 42,
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.args["some_field"] == "some_value"
        assert req.args["other_field"] == 42
        assert "input_type" not in req.args

    def test_parse_invalid_json_raises(self) -> None:
        """Malformed JSON raises JSONDecodeError."""
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("not valid json{{{")


class TestOpenAICodexParseStdinFlat:
    """Test parsing the flat generic format."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_parse_flat_shell_tool(self) -> None:
        """Flat format with tool_name/tool_input; event defaults to before_tool_use."""
        raw = json.dumps(
            {
                "tool_name": "shell",
                "tool_input": {"command": "rm -rf /"},
                "session_id": "flat-sess",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "shell"
        assert req.args["command"] == "rm -rf /"
        assert req.event == "before_tool_use"
        assert req.agent == "openai-codex"

    def test_parse_flat_with_no_tool_input(self) -> None:
        """Missing tool_input results in empty args."""
        raw = json.dumps(
            {
                "tool_name": "read_file",
                "session_id": "flat-sess-2",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "read_file"
        assert req.args == {}

    def test_parse_flat_preserves_context(self) -> None:
        """session_id and cwd are preserved in context."""
        raw = json.dumps(
            {
                "tool_name": "shell",
                "tool_input": {"command": "echo hi"},
                "session_id": "ctx-session",
                "cwd": "/home/user/proj",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "ctx-session"
        assert req.context["cwd"] == "/home/user/proj"


class TestOpenAICodexFormatResponse:
    """Test formatting responses for OpenAI Codex CLI."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_allow_returns_proceed(self) -> None:
        """Allow decision returns {"decision": "proceed"}, exit 0."""
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "proceed"
        assert exit_code == 0

    def test_deny_returns_block_json(self) -> None:
        """Deny decision returns {"decision": "block"} with a message."""
        resp = EvaluateResponse(decision="deny", reason="dangerous command")
        stdout, _ = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "block"
        assert "dangerous command" in parsed["message"]

    def test_deny_includes_reason_and_policy(self) -> None:
        """Deny message includes both reason and policy name."""
        resp = EvaluateResponse(
            decision="deny", reason="destructive operation", policy="safety-rule"
        )
        stdout, _ = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert "destructive operation" in parsed["message"]
        assert "safety-rule" in parsed["message"]

    def test_deny_exit_code_is_1(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 1

    def test_allow_exit_code_is_0(self) -> None:
        resp = EvaluateResponse(decision="allow")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 0

    def test_require_approval_returns_block(self) -> None:
        """require_approval returns block with approval message, exit 1."""
        resp = EvaluateResponse(decision="require_approval", reason="needs review")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "block"
        assert "approval" in parsed["message"].lower()
        assert exit_code == 1
