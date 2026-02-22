"""Tests for the hook fallback chain in HookAdapter.run().

Covers every step of the evaluation order:
1. Self-protection (always, no policy needed)
2. AVAKILL_POLICY env var → standalone eval
3. Running daemon → try_evaluate()
4. Auto-discover avakill.yaml / avakill.yml in cwd → standalone eval
5. No policy source → allow with stderr warning
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.claude_code import ClaudeCodeAdapter


def _make_stdin(tool: str = "Bash", args: dict | None = None) -> str:
    """Build a Claude Code PreToolUse JSON payload."""
    return json.dumps(
        {
            "session_id": "test-session",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": args or {"command": "echo hello"},
            "tool_use_id": "tu-test",
        }
    )


def _make_write_stdin(file_path: str, content: str = "x") -> str:
    """Build a Claude Code payload for a Write tool call."""
    return _make_stdin(
        tool="Write",
        args={"file_path": file_path, "content": content},
    )


class TestSelfProtectionInHook:
    """Step 1: Self-protection runs before any policy source."""

    def test_blocks_policy_file_write(self) -> None:
        adapter = ClaudeCodeAdapter()
        stdin = _make_write_stdin("/project/avakill.yaml")

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        # Should exit 0 (Claude Code uses JSON deny, not exit code)
        assert exc_info.value.code == 0

    def test_blocks_policy_file_write_response_is_deny(self, capsys: pytest.CaptureFixture) -> None:
        adapter = ClaudeCodeAdapter()
        stdin = _make_write_stdin("/project/avakill.yaml")

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Self-protection" in parsed["hookSpecificOutput"]["permissionDecisionReason"]

    def test_blocks_uninstall_command(self, capsys: pytest.CaptureFixture) -> None:
        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "pip uninstall avakill"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "uninstall" in parsed["hookSpecificOutput"]["permissionDecisionReason"].lower()

    @patch("avakill.hooks.base.HookAdapter._try_daemon")
    def test_self_protection_runs_before_daemon(
        self, mock_daemon: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Self-protection should block before daemon is even consulted."""
        adapter = ClaudeCodeAdapter()
        stdin = _make_write_stdin("/project/avakill.yaml")

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        mock_daemon.assert_not_called()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestFallbackChainEnvVar:
    """Step 2: AVAKILL_POLICY env var → standalone eval."""

    def test_env_var_policy_used_when_set(
        self,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: allow-all\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        monkeypatch.setenv("AVAKILL_POLICY", str(policy))

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        assert exc_info.value.code == 0

    def test_env_var_policy_deny_works(
        self,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        policy = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: deny-all\n"
            "    tools: ['*']\n"
            "    action: deny\n"
        )
        monkeypatch.setenv("AVAKILL_POLICY", str(policy))

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestFallbackChainDaemon:
    """Step 3: Running daemon → try_evaluate()."""

    @patch("avakill.hooks.base.HookAdapter._try_daemon")
    def test_daemon_response_used_when_available(
        self, mock_daemon: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        mock_daemon.return_value = EvaluateResponse(
            decision="deny", reason="daemon says no", policy="daemon-policy"
        )

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        mock_daemon.assert_called_once()
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "daemon says no" in parsed["hookSpecificOutput"]["permissionDecisionReason"]

    @patch("avakill.hooks.base.HookAdapter._try_local_policy")
    @patch("avakill.hooks.base.HookAdapter._try_daemon")
    def test_falls_through_when_daemon_unreachable(
        self, mock_daemon: MagicMock, mock_local: MagicMock
    ) -> None:
        mock_daemon.return_value = None
        mock_local.return_value = EvaluateResponse(decision="allow")

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        mock_daemon.assert_called_once()
        mock_local.assert_called_once()


class TestFallbackChainLocalPolicy:
    """Step 4: Auto-discover avakill.yaml / avakill.yml in cwd."""

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_discovers_avakill_yaml_in_cwd(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy = tmp_path / "avakill.yaml"  # type: ignore[operator]
        policy.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: allow-all\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        assert exc_info.value.code == 0

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_discovers_avakill_yml_in_cwd(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy = tmp_path / "avakill.yml"  # type: ignore[operator]
        policy.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: allow-all\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        assert exc_info.value.code == 0

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_yaml_preferred_over_yml(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """When both files exist, avakill.yaml should be used (checked first)."""
        yaml_policy = tmp_path / "avakill.yaml"  # type: ignore[operator]
        yaml_policy.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: yaml-deny\n"
            "    tools: ['*']\n"
            "    action: deny\n"
        )
        yml_policy = tmp_path / "avakill.yml"  # type: ignore[operator]
        yml_policy.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: yml-allow\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        # .yaml file has deny policy, so we should get a deny
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "yaml-deny" in parsed["hookSpecificOutput"]["permissionDecisionReason"]


class TestFallbackChainAllowWithWarning:
    """Step 5: No policy source → allow with stderr warning."""

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_allows_when_no_policy_source(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        assert exc_info.value.code == 0

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_warns_on_stderr(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        assert "no policy source found" in captured.err
        assert "avakill init --template hooks" in captured.err


class TestFailClosedMode:
    """Test AVAKILL_FAIL_CLOSED env var behavior."""

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_fail_closed_denies_when_no_policy_source(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)
        monkeypatch.setenv("AVAKILL_FAIL_CLOSED", "1")

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "AVAKILL_FAIL_CLOSED" in captured.err

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_fail_open_allows_when_env_not_set(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)
        monkeypatch.delenv("AVAKILL_FAIL_CLOSED", raising=False)

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit) as exc_info:
            adapter.run(stdin_data=stdin)

        assert exc_info.value.code == 0

    @patch("avakill.hooks.base.HookAdapter._try_daemon", return_value=None)
    def test_fail_closed_accepts_true_string(
        self,
        _mock_daemon: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AVAKILL_POLICY", raising=False)
        monkeypatch.setenv("AVAKILL_FAIL_CLOSED", "true")

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestFallbackChainOrder:
    """Verify the evaluation order is correct."""

    @patch("avakill.hooks.base.HookAdapter._try_local_policy")
    @patch("avakill.hooks.base.HookAdapter._try_daemon")
    def test_env_var_beats_daemon(
        self,
        mock_daemon: MagicMock,
        mock_local: MagicMock,
        tmp_path: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When AVAKILL_POLICY is set, daemon should not be consulted."""
        policy = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: allow-all\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        monkeypatch.setenv("AVAKILL_POLICY", str(policy))

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        mock_daemon.assert_not_called()
        mock_local.assert_not_called()

    @patch("avakill.hooks.base.HookAdapter._try_local_policy")
    @patch("avakill.hooks.base.HookAdapter._try_daemon")
    def test_daemon_beats_local_policy(self, mock_daemon: MagicMock, mock_local: MagicMock) -> None:
        """When daemon responds, local policy should not be consulted."""
        mock_daemon.return_value = EvaluateResponse(decision="allow")

        adapter = ClaudeCodeAdapter()
        stdin = _make_stdin(tool="Bash", args={"command": "ls"})

        with pytest.raises(SystemExit):
            adapter.run(stdin_data=stdin)

        mock_daemon.assert_called_once()
        mock_local.assert_not_called()
