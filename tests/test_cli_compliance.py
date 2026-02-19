"""Tests for the compliance CLI command group."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from avakill.cli.main import cli


def _make_policy_file(tmp_path: Path) -> Path:
    """Create a temporary policy file."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
        "  - name: approve-write\n"
        "    tools: [file_write]\n"
        "    action: require_approval\n"
    )
    return policy


class TestComplianceCLI:
    """Tests for the compliance command group."""

    def test_compliance_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "Compliance assessment" in result.output

    def test_report_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["compliance", "report", "--help"])
        assert result.exit_code == 0
        assert "--framework" in result.output
        assert "--format" in result.output
        assert "--output" in result.output

    def test_report_soc2_table(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        result = runner.invoke(
            cli,
            ["compliance", "report", "--framework", "soc2", "--policy", str(policy)],
        )
        assert result.exit_code == 0
        assert "SOC2" in result.output or "soc2" in result.output

    def test_report_all_frameworks(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        result = runner.invoke(
            cli,
            ["compliance", "report", "--framework", "all", "--policy", str(policy)],
        )
        assert result.exit_code == 0

    def test_report_json_format(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        result = runner.invoke(
            cli,
            [
                "compliance",
                "report",
                "--framework",
                "soc2",
                "--policy",
                str(policy),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["framework"] == "soc2"
        assert "controls" in data

    def test_report_markdown_format(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        result = runner.invoke(
            cli,
            [
                "compliance",
                "report",
                "--framework",
                "soc2",
                "--policy",
                str(policy),
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code == 0
        assert "# Compliance Report" in result.output
        assert "SOC2" in result.output or "soc2" in result.output

    def test_report_output_to_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        output_file = tmp_path / "report.md"
        result = runner.invoke(
            cli,
            [
                "compliance",
                "report",
                "--framework",
                "soc2",
                "--policy",
                str(policy),
                "--format",
                "markdown",
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "Compliance Report" in content

    def test_gaps_shows_remediation(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        result = runner.invoke(
            cli,
            ["compliance", "gaps", "--policy", str(policy)],
        )
        assert result.exit_code == 0
        # Without signing/logging, there should be gaps
        assert "gap" in result.output.lower() or "FAIL" in result.output

    def test_report_missing_policy_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["compliance", "report", "--policy", "/nonexistent/policy.yaml"],
        )
        assert result.exit_code == 1

    def test_gaps_missing_policy_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["compliance", "gaps", "--policy", "/nonexistent/policy.yaml"],
        )
        assert result.exit_code == 1
