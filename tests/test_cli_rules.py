"""Tests for the avakill rules command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.cli.rule_catalog import (
    ALL_RULES,
    classify_policy_rules,
    generate_yaml,
    get_default_on_ids,
    get_tool_presets,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def policy_yaml(tmp_path: Path) -> Path:
    """Create a minimal policy YAML file."""
    content = generate_yaml(list(get_default_on_ids()), default_action="allow")
    p = tmp_path / "avakill.yaml"
    p.write_text(content, encoding="utf-8")
    return p


@pytest.fixture
def mixed_policy_yaml(tmp_path: Path) -> Path:
    """Create a policy with catalog, scan, and custom rules."""
    data = yaml.safe_load(generate_yaml(["block-dangerous-shell"], default_action="allow"))
    # Add a scan rule
    data["policies"].insert(
        -1,
        {
            "name": "protect-env-files",
            "tools": ["file_write"],
            "action": "deny",
            "conditions": {"args_match": {"file_path": [".env"]}},
        },
    )
    # Add a custom rule
    data["policies"].insert(
        -1,
        {
            "name": "my-custom-block",
            "tools": ["Bash"],
            "action": "deny",
            "conditions": {"args_match": {"command": ["curl evil.com"]}},
            "message": "Blocked custom rule.",
        },
    )
    p = tmp_path / "avakill.yaml"
    p.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    return p


# ------------------------------------------------------------------
# classify_policy_rules tests
# ------------------------------------------------------------------


class TestClassifyPolicyRules:
    def test_catalog_rules_identified_by_name(self):
        """Catalog rules are matched by their rule_data name."""
        policies = [{"name": "block-catastrophic-shell", "tools": ["Bash"], "action": "deny"}]
        catalog_ids, scan_rules, custom_rules = classify_policy_rules(policies)
        assert "block-catastrophic-shell" in catalog_ids
        assert scan_rules == []
        assert custom_rules == []

    def test_base_rules_included_in_catalog_ids(self):
        """Base rules are also catalog rules (matched by name)."""
        base_names = [r.rule_data["name"] for r in ALL_RULES if r.base]
        policies = [{"name": n, "tools": ["Bash"], "action": "deny"} for n in base_names]
        catalog_ids, _scan, _custom = classify_policy_rules(policies)
        for r in ALL_RULES:
            if r.base:
                assert r.id in catalog_ids

    def test_scan_rules_by_pattern(self):
        """Rules matching protect-*-files pattern are classified as scan."""
        policies = [
            {"name": "protect-env-files", "tools": ["file_write"], "action": "deny"},
            {"name": "protect-key-files", "tools": ["file_write"], "action": "deny"},
        ]
        _catalog, scan_rules, _custom = classify_policy_rules(policies)
        assert len(scan_rules) == 2

    def test_log_all_is_scan(self):
        """log-all is classified as a system/scan rule, not custom."""
        policies = [{"name": "log-all", "tools": ["all"], "action": "allow"}]
        _catalog, scan_rules, custom_rules = classify_policy_rules(policies)
        assert len(scan_rules) == 1
        assert custom_rules == []

    def test_custom_rules_catchall(self):
        """Unknown rule names go to custom."""
        policies = [
            {"name": "my-special-rule", "tools": ["Bash"], "action": "deny"},
        ]
        _catalog, _scan, custom_rules = classify_policy_rules(policies)
        assert len(custom_rules) == 1
        assert custom_rules[0]["name"] == "my-special-rule"

    def test_mixed_policy_roundtrip(self):
        """Mixed policy correctly classifies all rule types."""
        policies = [
            {"name": "block-catastrophic-shell", "tools": ["Bash"], "action": "deny"},
            {"name": "block-dangerous-shell", "tools": ["Bash"], "action": "deny"},
            {"name": "protect-env-files", "tools": ["file_write"], "action": "deny"},
            {"name": "my-custom-rule", "tools": ["Bash"], "action": "deny"},
            {"name": "log-all", "tools": ["all"], "action": "allow"},
        ]
        catalog_ids, scan_rules, custom_rules = classify_policy_rules(policies)
        assert "block-catastrophic-shell" in catalog_ids
        assert "block-dangerous-shell" in catalog_ids
        assert len(scan_rules) == 2  # protect-env-files + log-all
        assert len(custom_rules) == 1


# ------------------------------------------------------------------
# get_tool_presets tests
# ------------------------------------------------------------------


class TestGetToolPresets:
    def test_returns_expected_keys(self):
        presets = get_tool_presets()
        assert "shell" in presets
        assert "write" in presets
        assert "read" in presets
        assert "sql" in presets
        assert "all" in presets

    def test_preset_values_are_nonempty(self):
        presets = get_tool_presets()
        for _key, (label, tools) in presets.items():
            assert label
            assert len(tools) > 0


# ------------------------------------------------------------------
# rules list tests
# ------------------------------------------------------------------


class TestRulesList:
    def test_shows_all_rules(self, runner: CliRunner, policy_yaml: Path) -> None:
        result = runner.invoke(cli, ["rules", "list", str(policy_yaml)])
        assert result.exit_code == 0
        assert "block-catastrophic-shell" in result.output
        assert "log-all" in result.output

    def test_handles_missing_policy(self, runner: CliRunner, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.yaml"
        result = runner.invoke(cli, ["rules", "list", str(missing)])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_correct_source_labels(self, runner: CliRunner, mixed_policy_yaml: Path) -> None:
        result = runner.invoke(cli, ["rules", "list", str(mixed_policy_yaml)])
        assert result.exit_code == 0
        assert "base" in result.output
        assert "catalog" in result.output
        assert "scan" in result.output
        assert "custom" in result.output
        assert "system" in result.output

    def test_shows_rule_count_and_default(self, runner: CliRunner, policy_yaml: Path) -> None:
        result = runner.invoke(cli, ["rules", "list", str(policy_yaml)])
        assert result.exit_code == 0
        assert "rules" in result.output
        assert "default:" in result.output


# ------------------------------------------------------------------
# rules edit (catalog) tests
# ------------------------------------------------------------------


class TestRulesEdit:
    def _run_edit(self, runner: CliRunner, policy_path: Path, input_: str) -> object:
        """Run rules edit with TTY patched."""
        with (
            patch("avakill.cli.rules_cmd._find_policy_path", return_value=policy_path),
            patch("avakill.cli.rules_cmd.sys") as mock_sys,
        ):
            mock_sys.stdin.isatty.return_value = True
            result = runner.invoke(cli, ["rules"], input=input_)
        return result

    def test_preserves_custom_rules_after_catalog_edit(
        self, runner: CliRunner, mixed_policy_yaml: Path
    ) -> None:
        """Custom rules survive a catalog edit session."""
        # Simulate: user presses Enter immediately (no changes) then 'n' for default action
        result = self._run_edit(runner, mixed_policy_yaml, "\nn\n")
        assert result.exit_code == 0
        # Reload and check custom rule still present
        data = yaml.safe_load(mixed_policy_yaml.read_text(encoding="utf-8"))
        names = [p["name"] for p in data["policies"]]
        assert "my-custom-block" in names

    def test_preserves_scan_rules(self, runner: CliRunner, mixed_policy_yaml: Path) -> None:
        """Scan rules survive a catalog edit session."""
        result = self._run_edit(runner, mixed_policy_yaml, "\nn\n")
        assert result.exit_code == 0
        data = yaml.safe_load(mixed_policy_yaml.read_text(encoding="utf-8"))
        names = [p["name"] for p in data["policies"]]
        assert "protect-env-files" in names

    def test_requires_tty(self, runner: CliRunner) -> None:
        """Non-TTY exits with helpful message."""
        with patch("avakill.cli.rules_cmd._find_policy_path", return_value=Path("avakill.yaml")):
            result = runner.invoke(cli, ["rules"], input=None)
        # CliRunner doesn't set isatty=True, so the command should fail
        assert result.exit_code == 1


# ------------------------------------------------------------------
# rules create tests
# ------------------------------------------------------------------


class TestRulesCreate:
    def _run_create(self, runner: CliRunner, policy: Path, input_: str) -> object:
        """Run rules create with TTY and policy path patched."""
        with (
            patch("avakill.cli.rules_cmd._find_policy_path", return_value=policy),
            patch("avakill.cli.rules_cmd.sys") as mock_sys,
        ):
            mock_sys.stdin.isatty.return_value = True
            result = runner.invoke(
                cli,
                ["rules", "create"],
                input=input_,
            )
        return result

    def _make_policy(self, tmp_path: Path, data: dict | None = None) -> Path:
        """Create a policy YAML in tmp_path."""
        if data is None:
            data = {"version": "1.0", "default_action": "deny", "policies": []}
        p = tmp_path / "avakill.yaml"
        p.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
        return p

    def test_minimal_rule(self, runner: CliRunner, tmp_path: Path) -> None:
        """Create a minimal rule with just name, tools, and action."""
        policy = self._make_policy(tmp_path)
        # Name, tools (1=shell), action (1=deny), no conditions/rate/msg
        result = self._run_create(runner, policy, "block-test\n1\n1\nn\nn\n\ny\n")
        assert result.exit_code == 0
        assert "block-test" in result.output
        data = yaml.safe_load(policy.read_text(encoding="utf-8"))
        names = [p["name"] for p in data["policies"]]
        assert "block-test" in names

    def test_rule_with_conditions(self, runner: CliRunner, tmp_path: Path) -> None:
        """Create a rule with argument matching conditions."""
        policy = self._make_policy(tmp_path)
        # Name, tools, action, conditions with arg match, no rate/msg
        result = self._run_create(
            runner,
            policy,
            "block-api\n1\n1\ny\ncommand\ncurl evil.com, wget bad.org\nn\nn\n\ny\n",
        )
        assert result.exit_code == 0
        data = yaml.safe_load(policy.read_text(encoding="utf-8"))
        rule = next(p for p in data["policies"] if p["name"] == "block-api")
        assert "conditions" in rule
        assert "curl evil.com" in rule["conditions"]["args_match"]["command"]

    def test_rule_with_rate_limit(self, runner: CliRunner, tmp_path: Path) -> None:
        """Create a rule with rate limiting."""
        policy = self._make_policy(tmp_path)
        # Name, tools (5=all), action (2=allow), rate limit only
        result = self._run_create(runner, policy, "rate-test\n5\n2\nn\ny\n5\n1m\n\ny\n")
        assert result.exit_code == 0
        data = yaml.safe_load(policy.read_text(encoding="utf-8"))
        rule = next(p for p in data["policies"] if p["name"] == "rate-test")
        assert rule["rate_limit"]["max_calls"] == 5
        assert rule["rate_limit"]["window"] == "1m"

    def test_appends_before_log_all(self, runner: CliRunner, tmp_path: Path) -> None:
        """New rules are inserted before the trailing log-all."""
        policy = self._make_policy(
            tmp_path,
            {
                "version": "1.0",
                "default_action": "allow",
                "policies": [
                    {"name": "log-all", "tools": ["all"], "action": "allow"},
                ],
            },
        )
        result = self._run_create(runner, policy, "custom-rule\n1\n1\nn\nn\n\ny\n")
        assert result.exit_code == 0
        reloaded = yaml.safe_load(policy.read_text(encoding="utf-8"))
        names = [p["name"] for p in reloaded["policies"]]
        assert names[-1] == "log-all"
        assert "custom-rule" in names
        assert names.index("custom-rule") < names.index("log-all")

    def test_name_collision_warning(self, runner: CliRunner, tmp_path: Path) -> None:
        """Warn when name matches a catalog rule."""
        policy = self._make_policy(tmp_path)
        # Use a name that collides with a catalog rule
        result = self._run_create(
            runner,
            policy,
            "block-catastrophic-shell\n1\n1\nn\nn\n\ny\n",
        )
        assert result.exit_code == 0
        assert "Warning" in result.output or "matches a catalog rule" in result.output
