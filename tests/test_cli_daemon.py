"""Tests for the daemon and evaluate CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    """Create a temporary policy YAML file."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
        "  - name: deny-delete\n"
        "    tools: [file_delete]\n"
        "    action: deny\n"
        "    message: Dangerous operation blocked\n"
    )
    return policy


# -------------------------------------------------------------------
# TestDaemonCLI
# -------------------------------------------------------------------


class TestDaemonCLI:
    def test_daemon_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["daemon", "--help"])
        assert result.exit_code == 0
        assert "Manage the AvaKill daemon" in result.output

    def test_start_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["daemon", "start", "--help"])
        assert result.exit_code == 0
        assert "--policy" in result.output
        assert "--socket" in result.output
        assert "--foreground" in result.output

    def test_stop_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["daemon", "stop", "--help"])
        assert result.exit_code == 0
        assert "--socket" in result.output

    def test_status_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["daemon", "status", "--help"])
        assert result.exit_code == 0
        assert "--socket" in result.output

    def test_status_not_running(self, runner: CliRunner):
        with patch("avakill.daemon.server.DaemonServer.is_running", return_value=(False, None)):
            result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 0
        assert "not running" in result.output

    def test_start_missing_policy_file_exits_1(self, runner: CliRunner):
        result = runner.invoke(cli, ["daemon", "start", "--policy", "/nonexistent/policy.yaml"])
        assert result.exit_code == 1
        assert "not found" in result.stderr


# -------------------------------------------------------------------
# TestEvaluateCLI
# -------------------------------------------------------------------


class TestEvaluateCLI:
    def test_evaluate_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["evaluate", "--help"])
        assert result.exit_code == 0
        assert "Evaluate a tool call" in result.output
        assert "--agent" in result.output
        assert "--policy" in result.output
        assert "--json" in result.output

    def test_evaluate_standalone_allow(self, runner: CliRunner, policy_file: Path):
        stdin_json = json.dumps({"tool": "file_read", "args": {"path": "/tmp/test.txt"}})
        result = runner.invoke(
            cli,
            ["evaluate", "--policy", str(policy_file)],
            input=stdin_json,
        )
        assert result.exit_code == 0
        assert "allow" in result.output

    def test_evaluate_standalone_deny_exits_2(self, runner: CliRunner, policy_file: Path):
        stdin_json = json.dumps({"tool": "file_delete", "args": {"path": "/etc/passwd"}})
        result = runner.invoke(
            cli,
            ["evaluate", "--policy", str(policy_file)],
            input=stdin_json,
        )
        assert result.exit_code == 2
        assert "deny" in result.output

    def test_evaluate_standalone_json_output(self, runner: CliRunner, policy_file: Path):
        stdin_json = json.dumps({"tool": "file_read", "args": {}})
        result = runner.invoke(
            cli,
            ["evaluate", "--policy", str(policy_file), "--json"],
            input=stdin_json,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["decision"] == "allow"
        assert "latency_ms" in data

    def test_evaluate_no_daemon_no_policy_exits_1(self, runner: CliRunner):
        stdin_json = json.dumps({"tool": "file_read", "args": {}})
        result = runner.invoke(
            cli,
            ["evaluate"],
            input=stdin_json,
        )
        assert result.exit_code == 1
        assert "daemon not running" in result.stderr or "not running" in result.stderr

    def test_evaluate_reads_stdin_json(self, runner: CliRunner, policy_file: Path):
        stdin_json = json.dumps({"tool": "file_read", "args": {"path": "foo.txt"}})
        result = runner.invoke(
            cli,
            ["evaluate", "--policy", str(policy_file)],
            input=stdin_json,
        )
        assert result.exit_code == 0
        assert "allow" in result.output

    def test_evaluate_empty_stdin_exits_1(self, runner: CliRunner):
        result = runner.invoke(cli, ["evaluate", "--policy", "x.yaml"], input="")
        assert result.exit_code == 1

    def test_evaluate_invalid_json_exits_1(self, runner: CliRunner):
        result = runner.invoke(cli, ["evaluate", "--policy", "x.yaml"], input="not json{")
        assert result.exit_code == 1
        assert "invalid JSON" in result.stderr

    def test_evaluate_missing_tool_field_exits_1(self, runner: CliRunner, policy_file: Path):
        stdin_json = json.dumps({"args": {"path": "/tmp/test.txt"}})
        result = runner.invoke(
            cli,
            ["evaluate", "--policy", str(policy_file)],
            input=stdin_json,
        )
        assert result.exit_code == 1
        assert "'tool' field required" in result.stderr
