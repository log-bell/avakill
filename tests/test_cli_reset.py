"""Tests for the avakill reset command."""

from __future__ import annotations

import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def avakill_dir(tmp_path: Path) -> Path:
    """Create a fake ~/.avakill/ directory."""
    d = tmp_path / ".avakill"
    d.mkdir()
    (d / "config.json").write_text("{}")
    (d / "audit.db").write_bytes(b"")
    (d / "avakill.pid").write_text("99999")
    return d


class TestResetRequiresTTY:
    def test_reset_requires_tty(self, runner: CliRunner) -> None:
        """Non-TTY without --confirm exits 1."""
        result = runner.invoke(cli, ["reset"], input=None)
        assert result.exit_code == 1
        assert "interactive terminal" in result.output


class TestResetConfirmPrompt:
    def test_reset_confirm_prompt_aborts_on_wrong_input(self, runner: CliRunner) -> None:
        """Typing something other than 'reset' aborts cleanly."""
        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.sys") as mock_sys,
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
        ):
            mock_sys.stdin.isatty.return_value = True
            mock_home = MagicMock()
            mock_avakill = MagicMock(is_dir=MagicMock(return_value=True))
            mock_home.__truediv__ = MagicMock(return_value=mock_avakill)
            mock_path_cls.home.return_value = mock_home
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset"], input="no\n")
        assert result.exit_code == 0
        assert "Aborted" in result.output


class TestResetRemovesAvakillDir:
    def test_reset_removes_avakill_dir(self, runner: CliRunner, avakill_dir: Path) -> None:
        """With --confirm, deletes ~/.avakill/."""
        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
        ):
            # Make Path.home() return tmp_path parent so .avakill resolves correctly
            mock_home_dir = avakill_dir.parent
            mock_path_cls.home.return_value = mock_home_dir
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        assert not avakill_dir.exists()
        assert "Deleted" in result.output


class TestResetUninstallsHooks:
    def test_reset_uninstalls_hooks(self, runner: CliRunner, tmp_path: Path) -> None:
        """Verifies uninstall_hook called for each installed hook."""
        avakill_dir = tmp_path / ".avakill"
        avakill_dir.mkdir()

        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=["claude-code", "cursor"]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
            patch("avakill.hooks.installer.uninstall_hook") as mock_uninstall,
        ):
            mock_path_cls.home.return_value = tmp_path
            mock_path_cls.cwd.return_value = Path.cwd()
            mock_uninstall.return_value = True
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        assert mock_uninstall.call_count == 2
        mock_uninstall.assert_any_call("claude-code")
        mock_uninstall.assert_any_call("cursor")


class TestResetStopsDaemon:
    def test_reset_stops_daemon(self, runner: CliRunner, tmp_path: Path) -> None:
        """Verifies SIGTERM sent to daemon PID."""
        avakill_dir = tmp_path / ".avakill"
        avakill_dir.mkdir()

        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(True, 12345)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
            patch("avakill.cli.reset_cmd.os.kill") as mock_kill,
        ):
            mock_path_cls.home.return_value = tmp_path
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)
        assert "Stopped daemon" in result.output


class TestResetUnwrapsMCP:
    def test_reset_unwraps_mcp(self, runner: CliRunner, tmp_path: Path) -> None:
        """Verifies MCP configs restored."""
        avakill_dir = tmp_path / ".avakill"
        avakill_dir.mkdir()

        mock_config = MagicMock()
        mock_config.path = tmp_path / "claude_desktop_config.json"

        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[mock_config]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
            patch("avakill.mcp.wrapper.unwrap_mcp_config") as mock_unwrap,
            patch("avakill.mcp.wrapper.write_mcp_config") as mock_write,
        ):
            mock_path_cls.home.return_value = tmp_path
            mock_path_cls.cwd.return_value = Path.cwd()
            mock_unwrapped = MagicMock()
            mock_unwrap.return_value = mock_unwrapped
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        mock_unwrap.assert_called_once_with(mock_config)
        mock_write.assert_called_once_with(mock_unwrapped)


class TestResetPolicyHandling:
    def test_reset_keeps_policy_by_default(self, runner: CliRunner, tmp_path: Path) -> None:
        """Policy file preserved without --include-policy."""
        avakill_dir = tmp_path / ".avakill"
        avakill_dir.mkdir()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\n")

        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
        ):
            mock_path_cls.home.return_value = tmp_path
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        assert policy.exists()

    def test_reset_deletes_policy_with_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        """`--include-policy` removes it."""
        avakill_dir = tmp_path / ".avakill"
        avakill_dir.mkdir()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\n")

        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[policy]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
        ):
            mock_path_cls.home.return_value = tmp_path
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset", "--confirm", "--include-policy"])
        assert result.exit_code == 0
        assert not policy.exists()


class TestResetNoopWhenNothingInstalled:
    def test_reset_noop_when_nothing_installed(self, runner: CliRunner, tmp_path: Path) -> None:
        """Graceful when nothing to clean."""
        with (
            patch("avakill.cli.reset_cmd._check_daemon", return_value=(False, None)),
            patch("avakill.cli.reset_cmd._check_hooks", return_value=[]),
            patch("avakill.cli.reset_cmd._check_mcp_wraps", return_value=[]),
            patch("avakill.cli.reset_cmd._find_policy_files", return_value=[]),
            patch("avakill.cli.reset_cmd.Path") as mock_path_cls,
        ):
            mock_home = MagicMock()
            mock_avakill_dir = MagicMock()
            mock_avakill_dir.is_dir.return_value = False
            mock_home.__truediv__ = MagicMock(return_value=mock_avakill_dir)
            mock_path_cls.home.return_value = mock_home
            mock_path_cls.cwd.return_value = Path.cwd()
            result = runner.invoke(cli, ["reset", "--confirm"])
        assert result.exit_code == 0
        assert "Nothing to clean up" in result.output
