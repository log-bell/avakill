"""Tests for avakill fix nudge in hook adapter deny output."""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.claude_code import ClaudeCodeAdapter
from avakill.hooks.cursor import CursorAdapter
from avakill.hooks.gemini_cli import GeminiCLIAdapter
from avakill.hooks.windsurf import WindsurfAdapter

_FIX_NUDGE = "avakill fix"


class TestClaudeCodeFixNudge:
    def test_deny_includes_fix_nudge(self) -> None:
        adapter = ClaudeCodeAdapter()
        resp = EvaluateResponse(decision="deny", reason="Blocked by policy", policy="test-rule")
        output, code = adapter.format_response(resp)
        assert output is not None
        payload = json.loads(output)
        reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        assert _FIX_NUDGE in reason

    def test_allow_has_no_fix_nudge(self) -> None:
        adapter = ClaudeCodeAdapter()
        resp = EvaluateResponse(decision="allow", reason=None, policy=None)
        output, code = adapter.format_response(resp)
        assert output is None


class TestGeminiCLIFixNudge:
    def test_deny_includes_fix_nudge(self) -> None:
        adapter = GeminiCLIAdapter()
        resp = EvaluateResponse(decision="deny", reason="Blocked", policy="test")
        output, code = adapter.format_response(resp)
        assert output is not None
        payload = json.loads(output)
        reason = payload["hookSpecificOutput"]["reason"]
        assert _FIX_NUDGE in reason


class TestCursorFixNudge:
    def test_deny_includes_fix_nudge(self) -> None:
        adapter = CursorAdapter()
        resp = EvaluateResponse(decision="deny", reason="Blocked", policy="test")
        output, code = adapter.format_response(resp)
        assert output is not None
        payload = json.loads(output)
        msg = payload["agentMessage"]
        assert _FIX_NUDGE in msg


class TestWindsurfFixNudge:
    def test_deny_includes_fix_nudge(self) -> None:
        adapter = WindsurfAdapter()
        resp = EvaluateResponse(decision="deny", reason="Blocked", policy="test")
        output, code = adapter.format_response(resp)
        assert output is not None
        assert _FIX_NUDGE in output
