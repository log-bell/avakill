"""Tests for avakill.cli.rule_catalog — composable rule definitions."""

from __future__ import annotations

import yaml

from avakill.cli.rule_catalog import (
    ALL_RULES,
    build_policy_dict,
    generate_yaml,
    get_base_rules,
    get_default_on_ids,
    get_optional_rule_ids,
    get_optional_rules,
    get_rule_by_id,
)
from avakill.core.models import PolicyConfig, PolicyRule


class TestRuleDefs:
    """Every rule_data in the catalog must be a valid PolicyRule."""

    def test_all_rule_data_validates(self):
        for rule in ALL_RULES:
            PolicyRule.model_validate(rule.rule_data)

    def test_no_duplicate_ids(self):
        ids = [r.id for r in ALL_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_no_duplicate_rule_names(self):
        names = [r.rule_data["name"] for r in ALL_RULES]
        assert len(names) == len(set(names)), f"Duplicate names: {names}"

    def test_catalog_size(self):
        assert len(ALL_RULES) == 12  # 3 base + 9 optional

    def test_base_rules_count(self):
        assert len(get_base_rules()) == 3

    def test_optional_rules_count(self):
        assert len(get_optional_rules()) == 9

    def test_base_rules_are_marked_base(self):
        for rule in get_base_rules():
            assert rule.base is True

    def test_optional_rules_are_not_base(self):
        for rule in get_optional_rules():
            assert rule.base is False


class TestGetRuleById:
    def test_returns_correct_rule(self):
        rule = get_rule_by_id("dangerous-shell")
        assert rule is not None
        assert rule.id == "dangerous-shell"

    def test_returns_none_for_unknown(self):
        assert get_rule_by_id("nonexistent-rule") is None

    def test_base_rule_lookup(self):
        rule = get_rule_by_id("catastrophic-shell")
        assert rule is not None
        assert rule.base is True


class TestGetOptionalRuleIds:
    def test_returns_all_optional_ids(self):
        ids = get_optional_rule_ids()
        assert len(ids) == 9
        assert "dangerous-shell" in ids
        assert "catastrophic-shell" not in ids  # base rule

    def test_order_matches_catalog(self):
        ids = get_optional_rule_ids()
        optional = get_optional_rules()
        assert ids == [r.id for r in optional]


class TestGetDefaultOnIds:
    def test_returns_default_on_rules(self):
        defaults = get_default_on_ids()
        assert "dangerous-shell" in defaults
        assert "destructive-sql" in defaults
        assert "destructive-tools" in defaults

    def test_excludes_default_off(self):
        defaults = get_default_on_ids()
        assert "package-install" not in defaults
        assert "web-rate-limit" not in defaults


class TestBuildPolicyDict:
    def test_empty_selection_includes_base_rules(self):
        result = build_policy_dict([])
        assert result["version"] == "1.0"
        assert result["default_action"] == "allow"
        names = [p["name"] for p in result["policies"]]
        assert "block-catastrophic-shell" in names
        assert "block-catastrophic-sql-shell" in names
        assert "block-catastrophic-sql-db" in names

    def test_selected_rules_included(self):
        result = build_policy_dict(["dangerous-shell", "web-rate-limit"])
        names = [p["name"] for p in result["policies"]]
        assert "block-dangerous-shell" in names
        assert "rate-limit-web-search" in names

    def test_selected_in_catalog_order(self):
        # web-rate-limit comes after dangerous-shell in catalog
        result = build_policy_dict(["web-rate-limit", "dangerous-shell"])
        names = [p["name"] for p in result["policies"]]
        shell_idx = names.index("block-dangerous-shell")
        web_idx = names.index("rate-limit-web-search")
        assert shell_idx < web_idx

    def test_log_all_appended_for_allow(self):
        result = build_policy_dict([], default_action="allow")
        names = [p["name"] for p in result["policies"]]
        assert names[-1] == "log-all"

    def test_no_log_all_for_deny(self):
        result = build_policy_dict([], default_action="deny")
        names = [p["name"] for p in result["policies"]]
        assert "log-all" not in names

    def test_extra_rules_after_optional(self):
        extra = [{"name": "scan-env", "tools": ["file_write"], "action": "deny"}]
        result = build_policy_dict(["dangerous-shell"], extra_rules=extra)
        names = [p["name"] for p in result["policies"]]
        shell_idx = names.index("block-dangerous-shell")
        scan_idx = names.index("scan-env")
        assert scan_idx > shell_idx

    def test_validates_as_policy_config(self):
        result = build_policy_dict(get_optional_rule_ids())
        PolicyConfig.model_validate(result)

    def test_deepcopy_prevents_mutation(self):
        """Calling build_policy_dict should not mutate the original rule_data."""
        original_rule = get_rule_by_id("web-rate-limit")
        assert original_rule is not None
        original_max = original_rule.rule_data["rate_limit"]["max_calls"]

        result = build_policy_dict(["web-rate-limit"])
        # Mutate the result
        for p in result["policies"]:
            if p["name"] == "rate-limit-web-search":
                p["rate_limit"]["max_calls"] = 999

        # Original should be unchanged
        assert original_rule.rule_data["rate_limit"]["max_calls"] == original_max


class TestGenerateYaml:
    def test_output_is_valid_yaml(self):
        output = generate_yaml([])
        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict)
        assert "policies" in parsed

    def test_output_validates_as_policy_config(self):
        output = generate_yaml(get_optional_rule_ids())
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_header_includes_base_rule_ids(self):
        output = generate_yaml([])
        assert "catastrophic-shell" in output
        assert "catastrophic-sql-shell" in output
        assert "catastrophic-sql-db" in output

    def test_header_includes_selected_ids(self):
        output = generate_yaml(["dangerous-shell", "web-rate-limit"])
        assert "Selected rules: dangerous-shell, web-rate-limit" in output

    def test_default_action_allow(self):
        output = generate_yaml([], default_action="allow")
        parsed = yaml.safe_load(output)
        assert parsed["default_action"] == "allow"

    def test_default_action_deny(self):
        output = generate_yaml([], default_action="deny")
        parsed = yaml.safe_load(output)
        assert parsed["default_action"] == "deny"

    def test_with_extra_rules(self):
        extra = [{"name": "custom-rule", "tools": ["all"], "action": "deny"}]
        output = generate_yaml(["dangerous-shell"], extra_rules=extra)
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert "custom-rule" in names
