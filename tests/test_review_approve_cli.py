"""Tests for the avakill review and approve CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def valid_proposed(tmp_path: Path) -> Path:
    """Create a valid proposed policy file."""
    f = tmp_path / "avakill.proposed.yaml"
    f.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
        "  - name: deny-delete\n"
        "    tools: [file_delete]\n"
        "    action: deny\n"
        "    message: No deleting\n"
    )
    return f


@pytest.fixture
def invalid_proposed(tmp_path: Path) -> Path:
    """Create an invalid proposed policy file."""
    f = tmp_path / "bad.proposed.yaml"
    f.write_text(
        "version: '2.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: test\n"
        "    tools: [foo]\n"
        "    action: allow\n"
    )
    return f


# -------------------------------------------------------------------
# Review command
# -------------------------------------------------------------------


class TestReviewCommand:
    def test_valid_policy(self, runner: CliRunner, valid_proposed: Path) -> None:
        result = runner.invoke(cli, ["review", str(valid_proposed)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_shows_rules(self, runner: CliRunner, valid_proposed: Path) -> None:
        result = runner.invoke(cli, ["review", str(valid_proposed)])
        assert result.exit_code == 0
        assert "allow-read" in result.output
        assert "deny-delete" in result.output

    def test_shows_approve_command(self, runner: CliRunner, valid_proposed: Path) -> None:
        result = runner.invoke(cli, ["review", str(valid_proposed)])
        assert result.exit_code == 0
        assert "avakill approve" in result.output

    def test_invalid_policy(self, runner: CliRunner, invalid_proposed: Path) -> None:
        result = runner.invoke(cli, ["review", str(invalid_proposed)])
        assert result.exit_code == 1

    def test_missing_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["review", "/nonexistent/policy.yaml"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_invalid_yaml(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("{{not: valid: yaml::")
        result = runner.invoke(cli, ["review", str(bad)])
        assert result.exit_code == 1

    def test_non_mapping_yaml(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "list.yaml"
        bad.write_text("- item1\n- item2\n")
        result = runner.invoke(cli, ["review", str(bad)])
        assert result.exit_code == 1
        assert "mapping" in result.output.lower()


# -------------------------------------------------------------------
# Approve command
# -------------------------------------------------------------------


class TestApproveCommand:
    def test_approve_with_confirmation(
        self, runner: CliRunner, valid_proposed: Path
    ) -> None:
        result = runner.invoke(
            cli, ["approve", str(valid_proposed)], input="y\n"
        )
        assert result.exit_code == 0
        assert "activated" in result.output.lower()
        # Check target file was created
        target = valid_proposed.parent / "avakill.yaml"
        assert target.exists()
        assert target.read_text() == valid_proposed.read_text()

    def test_approve_aborted(
        self, runner: CliRunner, valid_proposed: Path
    ) -> None:
        result = runner.invoke(
            cli, ["approve", str(valid_proposed)], input="n\n"
        )
        assert result.exit_code == 0
        assert "aborted" in result.output.lower()
        target = valid_proposed.parent / "avakill.yaml"
        assert not target.exists()

    def test_approve_yes_flag(
        self, runner: CliRunner, valid_proposed: Path
    ) -> None:
        result = runner.invoke(
            cli, ["approve", str(valid_proposed), "--yes"]
        )
        assert result.exit_code == 0
        assert "activated" in result.output.lower()
        target = valid_proposed.parent / "avakill.yaml"
        assert target.exists()

    def test_approve_custom_target(
        self, runner: CliRunner, valid_proposed: Path
    ) -> None:
        custom_target = valid_proposed.parent / "production.yaml"
        result = runner.invoke(
            cli,
            ["approve", str(valid_proposed), "--target", str(custom_target), "--yes"],
        )
        assert result.exit_code == 0
        assert custom_target.exists()
        assert custom_target.read_text() == valid_proposed.read_text()

    def test_approve_invalid_policy_rejected(
        self, runner: CliRunner, invalid_proposed: Path
    ) -> None:
        result = runner.invoke(
            cli, ["approve", str(invalid_proposed), "--yes"]
        )
        assert result.exit_code == 1

    def test_approve_missing_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["approve", "/nonexistent/policy.yaml", "--yes"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()


# -------------------------------------------------------------------
# CLI help
# -------------------------------------------------------------------


class TestCLIHelp:
    def test_review_in_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "review" in result.output

    def test_approve_in_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "approve" in result.output

    def test_review_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "proposed" in result.output.lower() or "review" in result.output.lower()

    def test_approve_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["approve", "--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower()
