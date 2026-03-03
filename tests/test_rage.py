"""Tests for AvaKill rage mode."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.core.rage import (
    _GENERIC_RAGE,
    RAGE_MESSAGES,
    is_rage_mode,
    ragify,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """Create a temp config dir with a default config."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({}), encoding="utf-8")
    return tmp_path


class TestIsRageMode:
    """Tests for is_rage_mode()."""

    def test_default_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AVAKILL_RAGE", raising=False)
        with patch("avakill.cli.config.get_config", return_value={}):
            assert is_rage_mode() is False

    def test_env_var_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        assert is_rage_mode() is True

    def test_env_var_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "true")
        assert is_rage_mode() is True

    def test_env_var_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "yes")
        assert is_rage_mode() is True

    def test_env_var_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "")
        with patch("avakill.cli.config.get_config", return_value={}):
            assert is_rage_mode() is False

    def test_config_rage_mode_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AVAKILL_RAGE", raising=False)
        with patch("avakill.cli.config.get_config", return_value={"rage_mode": True}):
            assert is_rage_mode() is True

    def test_config_rage_mode_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AVAKILL_RAGE", raising=False)
        with patch("avakill.cli.config.get_config", return_value={"rage_mode": False}):
            assert is_rage_mode() is False

    def test_config_import_error_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AVAKILL_RAGE", raising=False)
        with patch("avakill.cli.config.get_config", side_effect=ImportError):
            assert is_rage_mode() is False


class TestRagify:
    """Tests for ragify()."""

    def test_returns_original_when_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AVAKILL_RAGE", raising=False)
        with patch("avakill.cli.config.get_config", return_value={}):
            result = ragify("block-catastrophic-shell", "Dangerous command blocked.")
            assert result == "Dangerous command blocked."

    def test_prepends_rage_when_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        result = ragify("block-catastrophic-shell", "Dangerous command blocked.")
        assert result.startswith("\U0001f52a ")
        assert "Dangerous command blocked." in result
        assert RAGE_MESSAGES["block-catastrophic-shell"] in result

    def test_format_matches_spec(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        original = "Dangerous command blocked."
        result = ragify("block-catastrophic-shell", original)
        expected_rage = RAGE_MESSAGES["block-catastrophic-shell"]
        assert result == f"\U0001f52a {expected_rage}\n   {original}"

    def test_generic_fallback_for_unknown_rule(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        result = ragify("my-custom-rule-xyz", "Custom denial.")
        assert result.startswith("\U0001f52a ")
        assert "Custom denial." in result
        # The rage message should be one of the generic ones
        rage_line = result.split("\n")[0].replace("\U0001f52a ", "")
        assert rage_line in _GENERIC_RAGE

    def test_none_rule_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        result = ragify(None, "No rule name provided.")
        assert result.startswith("\U0001f52a ")
        assert "No rule name provided." in result

    def test_empty_string_rule_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AVAKILL_RAGE", "1")
        result = ragify("", "Empty rule name.")
        assert result.startswith("\U0001f52a ")
        assert "Empty rule name." in result


class TestRageMessagesCatalogCrossCheck:
    """Verify RAGE_MESSAGES keys match rule names in the catalog."""

    def test_all_rage_keys_are_valid_rule_names(self) -> None:
        from avakill.cli.rule_catalog import ALL_RULES

        catalog_names = {r.rule_data["name"] for r in ALL_RULES}
        for rage_key in RAGE_MESSAGES:
            assert rage_key in catalog_names, (
                f"RAGE_MESSAGES key {rage_key!r} does not match any rule name in the catalog"
            )


class TestRageCLI:
    """Tests for the avakill rage command."""

    def test_rage_on(self, runner: CliRunner, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("{}", encoding="utf-8")
        with patch("avakill.cli.config._CONFIG_PATH", config_path):
            result = runner.invoke(cli, ["rage", "on"])
            assert result.exit_code == 0
            assert "Rage mode ON" in result.output

            data = json.loads(config_path.read_text(encoding="utf-8"))
            assert data["rage_mode"] is True

    def test_rage_off(self, runner: CliRunner, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"rage_mode": True}), encoding="utf-8")
        with patch("avakill.cli.config._CONFIG_PATH", config_path):
            result = runner.invoke(cli, ["rage", "off"])
            assert result.exit_code == 0
            assert "Rage mode OFF" in result.output

            data = json.loads(config_path.read_text(encoding="utf-8"))
            assert data["rage_mode"] is False

    def test_rage_status_off(self, runner: CliRunner, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("{}", encoding="utf-8")
        with patch("avakill.cli.config._CONFIG_PATH", config_path):
            result = runner.invoke(cli, ["rage", "status"])
            assert result.exit_code == 0
            assert "Rage mode: OFF" in result.output

    def test_rage_status_on(self, runner: CliRunner, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"rage_mode": True}), encoding="utf-8")
        with patch("avakill.cli.config._CONFIG_PATH", config_path):
            result = runner.invoke(cli, ["rage", "status"])
            assert result.exit_code == 0
            assert "Rage mode: ON" in result.output

    def test_rage_invalid_arg(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["rage", "maybe"])
        assert result.exit_code != 0
