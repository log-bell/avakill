"""Tests for the AvaKill CLI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.core.models import AuditEvent, Decision, ToolCall
from avakill.logging.sqlite_logger import SQLiteLogger


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """Create a temporary dir with a valid policy file."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
        "  - name: deny-delete\n"
        "    tools: [file_delete, shell_exec]\n"
        "    action: deny\n"
        "    conditions:\n"
        "      args_match:\n"
        "        cmd: ['rm -rf']\n"
        "    message: Dangerous!\n"
    )
    return tmp_path


@pytest.fixture
def db_with_events(tmp_path: Path) -> Path:
    """Create a temp database with sample events."""
    db_path = tmp_path / "test_audit.db"

    async def _seed():
        logger = SQLiteLogger(str(db_path))
        try:
            await logger._ensure_db()
            for i in range(5):
                allowed = i % 2 == 0
                action = "allow" if allowed else "deny"
                event = AuditEvent(
                    tool_call=ToolCall(
                        tool_name=f"tool_{i}",
                        arguments={"key": f"value_{i}"},
                        agent_id="test-agent",
                        session_id="test-session",
                    ),
                    decision=Decision(
                        allowed=allowed,
                        action=action,
                        policy_name=f"policy-{i}",
                        reason=f"Test reason {i}",
                    ),
                )
                await logger.log(event)
            await logger.flush()
        finally:
            await logger.close()

    asyncio.run(_seed())
    return db_path


# ---------------------------------------------------------------
# CLI help and version
# ---------------------------------------------------------------


class TestCLIBasics:
    def test_cli_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AvaKill" in result.output
        assert "approve" in result.output
        assert "init" in result.output
        assert "dashboard" in result.output
        assert "logs" in result.output
        assert "mcp-proxy" in result.output
        assert "review" in result.output
        assert "validate" in result.output
        assert "sign" in result.output
        assert "verify" in result.output
        assert "fix" in result.output

    def test_cli_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestLazyGroup:
    """Tests for lazy CLI import mechanism."""

    def test_lazy_group_lists_all_commands(self, runner: CliRunner) -> None:
        from avakill.cli.main import _COMMANDS

        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for cmd_name in _COMMANDS:
            assert cmd_name in result.output, f"Command {cmd_name!r} missing from --help"

    def test_help_does_not_import_unrelated_modules(self) -> None:
        """Listing commands should not import heavy subcommand modules."""
        import sys

        # Remove any cached imports of evaluate_cmd
        mod_key = "avakill.cli.evaluate_cmd"
        was_loaded = mod_key in sys.modules
        if was_loaded:
            # Already loaded from prior tests — skip this check
            return

        from avakill.cli.main import _COMMANDS, LazyGroup

        ctx = click.Context(click.Command("dummy"))
        group = LazyGroup()
        names = group.list_commands(ctx)
        assert len(names) == len(_COMMANDS)
        # list_commands should not have triggered any imports
        assert mod_key not in sys.modules

    def test_evaluate_subcommand_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["evaluate", "--help"])
        assert result.exit_code == 0
        assert "tool" in result.output.lower()


# ---------------------------------------------------------------
# Init command
# ---------------------------------------------------------------


class TestInitCommand:
    def test_init_default_template(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "avakill.yaml"
        result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "version" in content
        assert "default_action" in content

    def test_init_strict_template(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "avakill.yaml"
        result = runner.invoke(cli, ["init", "--template", "strict", "--output", str(output)])
        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "strict" in content.lower() or "deny" in content

    def test_init_permissive_template(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "avakill.yaml"
        result = runner.invoke(cli, ["init", "--template", "permissive", "--output", str(output)])
        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "default_action: allow" in content

    def test_init_generates_valid_policy(self, runner: CliRunner, tmp_path: Path) -> None:
        """The generated file should be loadable by the policy engine."""
        from avakill.core.policy import PolicyEngine

        output = tmp_path / "avakill.yaml"
        runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        engine = PolicyEngine.from_yaml(output)
        assert engine.config.version == "1.0"
        assert len(engine.config.policies) > 0

    def test_init_detects_frameworks(self, runner: CliRunner, tmp_path: Path) -> None:
        """When pyproject.toml mentions openai, init should detect it."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["openai>=1.0"]\n')
        output = tmp_path / "avakill.yaml"

        with patch("avakill.cli.init_cmd.Path.cwd", return_value=tmp_path):
            result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])

        assert result.exit_code == 0
        assert "openai" in result.output.lower()

    def test_init_no_overwrite_without_confirm(self, runner: CliRunner, tmp_path: Path) -> None:
        output = tmp_path / "avakill.yaml"
        output.write_text("existing content")

        result = runner.invoke(
            cli,
            ["init", "--template", "default", "--output", str(output)],
            input="n\n",
        )
        assert result.exit_code == 0
        assert output.read_text() == "existing content"

    def test_init_next_steps_uses_output_filename(self, runner: CliRunner, tmp_path: Path) -> None:
        """Step 1 should reflect the --output filename, not hardcode avakill.yaml."""
        output = tmp_path / "custom.yaml"
        result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        assert result.exit_code == 0
        assert "custom.yaml" in result.output
        # Should NOT reference the default name when a custom one is given
        assert "avakill.yaml" not in result.output.split("Next steps")[1]

    def test_init_no_snippet_reference_without_frameworks(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """When no frameworks are detected, 'see snippet above' must not appear."""
        output = tmp_path / "avakill.yaml"
        with patch("avakill.cli.init_cmd.Path.cwd", return_value=tmp_path):
            result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        assert result.exit_code == 0
        assert "see snippet above" not in result.output

    def test_init_snippet_reference_with_frameworks(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """When frameworks are detected, 'see snippet above' should appear."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["openai>=1.0"]\n')
        output = tmp_path / "avakill.yaml"
        with patch("avakill.cli.init_cmd.Path.cwd", return_value=tmp_path):
            result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        assert result.exit_code == 0
        assert "see snippet above" in result.output

    def test_init_mentions_audit_logging_before_dashboard(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Audit logging step should appear before dashboard step."""
        output = tmp_path / "avakill.yaml"
        result = runner.invoke(cli, ["init", "--template", "default", "--output", str(output)])
        assert result.exit_code == 0
        out = result.output.lower()
        audit_pos = out.find("audit logging")
        dashboard_pos = out.find("dashboard")
        assert audit_pos != -1, "audit logging not mentioned in output"
        assert dashboard_pos != -1, "dashboard not mentioned in output"
        assert audit_pos < dashboard_pos, "audit logging should appear before dashboard"


# ---------------------------------------------------------------
# Validate command
# ---------------------------------------------------------------


class TestValidateCommand:
    def test_validate_valid_policy(self, runner: CliRunner, policy_dir: Path) -> None:
        result = runner.invoke(cli, ["validate", str(policy_dir / "avakill.yaml")])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_shows_rules(self, runner: CliRunner, policy_dir: Path) -> None:
        result = runner.invoke(cli, ["validate", str(policy_dir / "avakill.yaml")])
        assert result.exit_code == 0
        assert "allow-read" in result.output
        assert "deny-delete" in result.output

    def test_validate_invalid_yaml(self, runner: CliRunner, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{not: valid: yaml::")
        result = runner.invoke(cli, ["validate", str(bad_file)])
        assert result.exit_code == 1

    def test_validate_invalid_schema(self, runner: CliRunner, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(
            "version: '2.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: test\n"
            "    tools: [foo]\n"
            "    action: allow\n"
        )
        result = runner.invoke(cli, ["validate", str(bad_file)])
        assert result.exit_code == 1

    def test_validate_missing_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate", "/nonexistent/policy.yaml"])
        assert result.exit_code == 1

    def test_validate_all_templates(self, runner: CliRunner) -> None:
        """All bundled templates should pass validation."""
        templates_dir = Path(__file__).resolve().parent.parent / "src" / "avakill" / "templates"
        for template_file in templates_dir.glob("*.yaml"):
            result = runner.invoke(cli, ["validate", str(template_file)])
            assert result.exit_code == 0, f"Template {template_file.name} failed validation"


# ---------------------------------------------------------------
# Logs command
# ---------------------------------------------------------------


class TestLogsCommand:
    def test_logs_table_format(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(cli, ["logs", "--db", str(db_with_events)])
        assert result.exit_code == 0
        assert "tool_0" in result.output or "tool_1" in result.output

    def test_logs_json_format(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(cli, ["logs", "--db", str(db_with_events), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        assert "tool" in data[0]
        assert "action" in data[0]

    def test_logs_json_valid_structure(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(cli, ["logs", "--db", str(db_with_events), "--json"])
        data = json.loads(result.output)
        for record in data:
            assert "id" in record
            assert "timestamp" in record
            assert "tool" in record
            assert "allowed" in record
            assert "action" in record

    def test_logs_limit(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(cli, ["logs", "--db", str(db_with_events), "--json", "--limit", "2"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_logs_denied_only(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(
            cli, ["logs", "--db", str(db_with_events), "--json", "--denied-only"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for record in data:
            assert record["allowed"] is False

    def test_logs_tool_filter(self, runner: CliRunner, db_with_events: Path) -> None:
        result = runner.invoke(
            cli, ["logs", "--db", str(db_with_events), "--json", "--tool", "tool_0"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for record in data:
            assert record["tool"] == "tool_0"

    def test_logs_missing_db(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["logs", "--db", "/nonexistent/db.sqlite"])
        assert result.exit_code == 1

    def test_logs_empty_db(self, runner: CliRunner, tmp_path: Path) -> None:
        db_path = tmp_path / "empty.db"

        async def _create():
            logger = SQLiteLogger(str(db_path))
            await logger._ensure_db()
            await logger.close()

        asyncio.run(_create())

        result = runner.invoke(cli, ["logs", "--db", str(db_path)])
        assert result.exit_code == 0
        assert "No events" in result.output


# ---------------------------------------------------------------
# MCP proxy command
# ---------------------------------------------------------------


class TestMCPProxyCommand:
    def test_mcp_proxy_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["mcp-proxy", "--help"])
        assert result.exit_code == 0
        assert "upstream-cmd" in result.output
        assert "policy" in result.output

    def test_mcp_proxy_missing_policy(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "mcp-proxy",
                "--upstream-cmd",
                "echo",
                "--policy",
                "/nonexistent/policy.yaml",
            ],
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------
# Dashboard command
# ---------------------------------------------------------------


class TestDashboardCommand:
    def test_dashboard_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "db" in result.output
        assert "refresh" in result.output

    def test_dashboard_layout_renders(self) -> None:
        """Verify the layout builder doesn't crash with empty data."""
        from avakill.cli.dashboard_cmd import _build_layout

        layout = _build_layout({}, [])
        assert layout is not None

    def test_dashboard_layout_with_stats(self) -> None:
        """Verify layout renders with real stats."""
        from avakill.cli.dashboard_cmd import _build_layout

        stats = {
            "total_events": 100,
            "allowed": 80,
            "denied": 20,
            "top_denied_tools": [("shell_exec", 15), ("db_drop", 5)],
        }
        events = [
            AuditEvent(
                tool_call=ToolCall(
                    tool_name="shell_exec",
                    arguments={"cmd": "rm -rf /"},
                ),
                decision=Decision(
                    allowed=False,
                    action="deny",
                    policy_name="block-dangerous",
                    reason="Blocked",
                ),
            ),
        ]
        layout = _build_layout(stats, events)
        assert layout is not None

    def test_dashboard_header_panel(self) -> None:
        from avakill.cli.dashboard_cmd import _make_header

        panel = _make_header({"total_events": 50, "allowed": 40, "denied": 10})
        assert panel is not None

    def test_dashboard_empty_denied_bar(self) -> None:
        from avakill.cli.dashboard_cmd import _make_denied_bar

        panel = _make_denied_bar({"top_denied_tools": []})
        assert panel is not None

    def test_dashboard_event_table_empty(self) -> None:
        from avakill.cli.dashboard_cmd import _make_event_table

        panel = _make_event_table([])
        assert panel is not None
