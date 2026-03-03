"""Tests for the Amp CLI hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.amp import AmpAdapter


class TestAmpParseStdin:
    """Test parsing Amp CLI tool payloads."""

    def setup_method(self) -> None:
        self.adapter = AmpAdapter()

    def test_parse_with_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Bash")
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        raw = json.dumps({"command": "ls -la"})
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "Bash"
        assert req.args == {"command": "ls -la"}
        assert req.agent == "amp"
        assert req.event == "pre_tool_use"

    def test_parse_missing_env_var_defaults_to_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENT_TOOL_NAME", raising=False)
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        raw = json.dumps({"file": "/tmp/test.txt"})
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "unknown"

    def test_parse_preserves_thread_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Write")
        monkeypatch.setenv("AGENT_THREAD_ID", "thread-42")
        raw = json.dumps({"path": "/tmp/out.txt"})
        req = self.adapter.parse_stdin(raw)
        assert req.context["thread_id"] == "thread-42"

    def test_parse_empty_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Bash")
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        req = self.adapter.parse_stdin("")
        assert req.args == {}

    def test_parse_whitespace_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Bash")
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        req = self.adapter.parse_stdin("   \n  ")
        assert req.args == {}

    def test_parse_non_dict_json_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Bash")
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        raw = json.dumps("just a string")
        req = self.adapter.parse_stdin(raw)
        assert req.args == {"raw": "just a string"}

    def test_parse_invalid_json_returns_empty_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_TOOL_NAME", "Bash")
        monkeypatch.delenv("AGENT_THREAD_ID", raising=False)
        req = self.adapter.parse_stdin("{bad json")
        assert req.args == {}


class TestAmpFormatResponse:
    """Test formatting responses for Amp CLI."""

    def setup_method(self) -> None:
        self.adapter = AmpAdapter()

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

    def test_require_approval_exits_1(self) -> None:
        resp = EvaluateResponse(decision="require_approval")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is None
        assert exit_code == 1  # Amp native "ask" support

    def test_deny_no_policy_adds_fix_hint(self, capsys: pytest.CaptureFixture) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        self.adapter.format_response(resp)
        captured = capsys.readouterr()
        assert "avakill fix" in captured.err
