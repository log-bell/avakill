"""Tests for agent detection and hook installation logic."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from avakill.hooks.installer import (
    HookInstallResult,
    detect_agents,
    install_hook,
    list_installed_hooks,
    uninstall_hook,
)


class TestDetectAgents:
    """Test agent detection."""

    def test_detect_claude_code_by_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        detected = detect_agents()
        assert "claude-code" in detected

    def test_detect_no_agents_when_none_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)
        detected = detect_agents()
        assert detected == []

    def test_detect_multiple_agents(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".gemini").mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        detected = detect_agents()
        assert "claude-code" in detected
        assert "gemini-cli" in detected


class TestInstallHook:
    """Test hook installation into agent configs."""

    def test_install_claude_code_creates_settings_entry(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        result = install_hook("claude-code", config_path=config_path)

        assert isinstance(result, HookInstallResult)
        assert result.config_path == config_path
        data = json.loads(config_path.read_text())
        hooks = data["hooks"]["PreToolUse"]
        assert len(hooks) == 1
        assert any("avakill" in str(h) for h in hooks)

    def test_install_resolves_absolute_path(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        result = install_hook("claude-code", config_path=config_path)
        # Command should contain an absolute path (/ or \) when binary is found
        # or a bare name with a warning when it isn't
        if "/" in result.command or "\\" in result.command:
            assert Path(result.command).name.startswith("avakill-hook-")
        else:
            assert any("Could not find" in w for w in result.warnings)

    @patch("avakill.hooks.installer._smoke_test", return_value=True)
    def test_install_smoke_test_passes(self, _mock: object, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        result = install_hook("claude-code", config_path=config_path)
        assert result.smoke_test_passed is True
        assert not any("Smoke test failed" in w for w in result.warnings)

    @patch("avakill.hooks.installer._smoke_test", return_value=False)
    def test_install_smoke_test_failure_warns(self, _mock: object, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        result = install_hook("claude-code", config_path=config_path)
        assert result.smoke_test_passed is False
        assert any("Smoke test failed" in w for w in result.warnings)

    def test_install_claude_code_preserves_existing_hooks(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        existing = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "my-hook.sh"}],
                    }
                ]
            }
        }
        config_path.write_text(json.dumps(existing))

        install_hook("claude-code", config_path=config_path)

        data = json.loads(config_path.read_text())
        hooks = data["hooks"]["PreToolUse"]
        assert len(hooks) == 2  # original + avakill

    def test_install_cursor_creates_hooks_json(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".cursor" / "hooks.json"
        install_hook("cursor", config_path=config_path)

        data = json.loads(config_path.read_text())
        hooks = data["hooks"]["beforeShellExecution"]
        assert len(hooks) == 1

    def test_install_windsurf_creates_hooks_json(self, tmp_path: Path) -> None:
        config_path = tmp_path / "hooks.json"
        install_hook("windsurf", config_path=config_path)

        data = json.loads(config_path.read_text())
        hooks = data["hooks"]["pre_run_command"]
        assert len(hooks) == 1
        assert hooks[0]["show_output"] is True

    def test_install_gemini_cli_creates_settings(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        install_hook("gemini-cli", config_path=config_path)

        data = json.loads(config_path.read_text())
        hooks = data["hooks"]["BeforeTool"]
        assert len(hooks) == 1

    def test_install_idempotent(self, tmp_path: Path) -> None:
        """Running install twice doesn't duplicate the hook."""
        config_path = tmp_path / "settings.json"
        install_hook("claude-code", config_path=config_path)
        install_hook("claude-code", config_path=config_path)

        data = json.loads(config_path.read_text())
        avakill_hooks = [
            h
            for h in data["hooks"]["PreToolUse"]
            if any("avakill" in str(sub) for sub in h.get("hooks", []))
        ]
        assert len(avakill_hooks) == 1

    def test_install_unknown_agent_raises(self) -> None:
        with pytest.raises(KeyError, match="unknown agent"):
            install_hook("unknown-agent")


class TestUninstallHook:
    """Test hook uninstallation."""

    def test_uninstall_removes_hook_entry(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        install_hook("claude-code", config_path=config_path)
        assert uninstall_hook("claude-code", config_path=config_path) is True

        data = json.loads(config_path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 0

    def test_uninstall_nonexistent_returns_false(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        assert uninstall_hook("claude-code", config_path=config_path) is False


class TestCursorConfigPathLazy:
    """Test that Cursor config path is evaluated lazily (respects cwd)."""

    def test_cursor_config_path_respects_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cursor config_path should be based on cwd at call time, not import time."""
        project_a = tmp_path / "project_a"
        project_b = tmp_path / "project_b"
        project_a.mkdir()
        project_b.mkdir()

        # Install in project_a
        monkeypatch.chdir(project_a)
        result_a = install_hook("cursor")
        assert "project_a" in str(result_a.config_path)

        # Install in project_b — should resolve to project_b, not project_a
        monkeypatch.chdir(project_b)
        result_b = install_hook("cursor")
        assert "project_b" in str(result_b.config_path)
        assert result_a.config_path != result_b.config_path


class TestListInstalledHooks:
    """Test listing hook installation status."""

    def test_list_shows_installed_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_path = tmp_path / ".claude" / "settings.json"
        install_hook("claude-code", config_path=config_path)

        from avakill.hooks import installer

        monkeypatch.setitem(
            installer._AGENT_CONFIG["claude-code"],  # type: ignore[arg-type]
            "config_path",
            config_path,
        )

        result = list_installed_hooks()
        assert result["claude-code"] is True
