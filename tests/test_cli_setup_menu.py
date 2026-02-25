"""Tests for the interactive rule menu in avakill setup."""

from __future__ import annotations

import yaml

from avakill.cli.rule_catalog import (
    generate_yaml,
    get_base_rules,
    get_default_on_ids,
)
from avakill.core.models import PolicyConfig


class TestDefaultSelections:
    def test_default_on_rules_produce_valid_policy(self):
        defaults = list(get_default_on_ids())
        output = generate_yaml(defaults, default_action="allow")
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_includes_expected_rules(self):
        defaults = list(get_default_on_ids())
        output = generate_yaml(defaults)
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        # Base rules always present
        assert "block-catastrophic-shell" in names
        # Default-on optional rules
        assert "block-dangerous-shell" in names
        assert "block-destructive-sql" in names
        assert "block-destructive-tools" in names

    def test_default_selection_has_log_all_trailer(self):
        defaults = list(get_default_on_ids())
        output = generate_yaml(defaults, default_action="allow")
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert names[-1] == "log-all"


class TestToggleRuleOff:
    def test_removing_default_on_rule(self):
        """Toggling dangerous-shell off should exclude it."""
        defaults = set(get_default_on_ids())
        defaults.discard("block-dangerous-shell")
        output = generate_yaml(list(defaults))
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert "block-dangerous-shell" not in names
        # Other default-on rules still present
        assert "block-destructive-sql" in names

    def test_empty_selection_only_base_and_log_all(self):
        output = generate_yaml([], default_action="allow")
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        # Only base rules + log-all
        assert len(names) == len(get_base_rules()) + 1
        assert names[-1] == "log-all"


class TestDefaultActionDeny:
    def test_deny_reflected_in_yaml(self):
        output = generate_yaml(["block-dangerous-shell"], default_action="deny")
        parsed = yaml.safe_load(output)
        assert parsed["default_action"] == "deny"

    def test_deny_has_no_log_all(self):
        output = generate_yaml(["block-dangerous-shell"], default_action="deny")
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert "log-all" not in names


class TestScanIntegration:
    def test_scan_rules_added_to_output(self):
        extra = [
            {
                "name": "protect-env-files",
                "tools": ["file_write", "file_delete"],
                "action": "deny",
                "conditions": {"args_match": {"file_path": [".env"]}},
                "message": "Detected env file(s)",
            }
        ]
        output = generate_yaml(["block-dangerous-shell"], extra_rules=extra)
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert "protect-env-files" in names
        PolicyConfig.model_validate(parsed)

    def test_scan_rules_come_after_optional_before_log_all(self):
        extra = [{"name": "scan-rule", "tools": ["file_write"], "action": "deny"}]
        output = generate_yaml(["block-dangerous-shell"], default_action="allow", extra_rules=extra)
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        scan_idx = names.index("scan-rule")
        shell_idx = names.index("block-dangerous-shell")
        log_idx = names.index("log-all")
        assert shell_idx < scan_idx < log_idx
