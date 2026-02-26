"""Tests for avakill.cli.rule_catalog — composable rule definitions."""

from __future__ import annotations

import yaml

from avakill.cli.rule_catalog import (
    ALL_RULES,
    CATEGORY_DISPLAY,
    build_policy_dict,
    generate_yaml,
    get_base_rules,
    get_default_on_ids,
    get_optional_rule_ids,
    get_optional_rules,
    get_optional_rules_by_category,
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
        assert len(ALL_RULES) == 84

    def test_base_rules_count(self):
        assert len(get_base_rules()) == 3

    def test_optional_rules_count(self):
        assert len(get_optional_rules()) == 81

    def test_base_rules_are_marked_base(self):
        for rule in get_base_rules():
            assert rule.base is True

    def test_optional_rules_are_not_base(self):
        for rule in get_optional_rules():
            assert rule.base is False


class TestGetRuleById:
    def test_returns_correct_rule(self):
        rule = get_rule_by_id("block-dangerous-shell")
        assert rule is not None
        assert rule.id == "block-dangerous-shell"

    def test_returns_none_for_unknown(self):
        assert get_rule_by_id("nonexistent-rule") is None

    def test_base_rule_lookup(self):
        rule = get_rule_by_id("block-catastrophic-shell")
        assert rule is not None
        assert rule.base is True

    def test_t2_rule_lookup(self):
        rule = get_rule_by_id("block-catastrophic-deletion")
        assert rule is not None
        assert rule.tier == 2


class TestGetOptionalRuleIds:
    def test_returns_all_optional_ids(self):
        ids = get_optional_rule_ids()
        assert len(ids) == 81
        assert "block-dangerous-shell" in ids
        assert "block-catastrophic-shell" not in ids  # base rule
        # T2 rules included
        assert "block-catastrophic-deletion" in ids
        assert "enforce-workspace-boundary" in ids

    def test_order_matches_catalog(self):
        ids = get_optional_rule_ids()
        optional = get_optional_rules()
        assert ids == [r.id for r in optional]


class TestGetDefaultOnIds:
    def test_returns_default_on_rules(self):
        defaults = get_default_on_ids()
        assert "block-dangerous-shell" in defaults
        assert "block-destructive-sql" in defaults
        assert "block-destructive-tools" in defaults
        # T2 default-on rules
        assert "block-catastrophic-deletion" in defaults
        assert "block-ssh-key-access" in defaults
        assert "block-cloud-credentials" in defaults
        # T5 default-on rules
        assert "detect-secrets-outbound" in defaults

    def test_excludes_default_off(self):
        defaults = get_default_on_ids()
        assert "approve-package-installs" not in defaults
        assert "rate-limit-web-search" not in defaults
        assert "enforce-workspace-boundary" not in defaults
        assert "detect-prompt-injection" not in defaults


class TestT2Rules:
    """T2 path-resolution rules have correct structure."""

    def test_t2_rules_have_path_conditions(self):
        """All tier=2 rules use path_match or path_not_match."""
        t2_rules = [r for r in ALL_RULES if r.tier == 2]
        assert len(t2_rules) == 14
        for rule in t2_rules:
            conditions = rule.rule_data.get("conditions", {})
            has_path = "path_match" in conditions or "path_not_match" in conditions
            assert has_path, f"T2 rule {rule.id} lacks path_match/path_not_match"

    def test_t2_rules_generate_valid_yaml(self):
        """generate_yaml() with T2 rules produces valid PolicyConfig."""
        t2_ids = [r.id for r in ALL_RULES if r.tier == 2]
        output = generate_yaml(t2_ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_t2_rule_tiers(self):
        """All T2 rules have tier=2."""
        t2_rules = [r for r in ALL_RULES if r.tier == 2]
        for rule in t2_rules:
            assert rule.tier == 2, f"{rule.id} has tier={rule.tier}"

    def test_t1_rules_have_tier_1(self):
        """All T1 rules have tier=1."""
        t1_rules = [r for r in ALL_RULES if r.tier == 1]
        assert len(t1_rules) == 62  # 3 base + 9 T1 + 50 new T1


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
        result = build_policy_dict(["block-dangerous-shell", "rate-limit-web-search"])
        names = [p["name"] for p in result["policies"]]
        assert "block-dangerous-shell" in names
        assert "rate-limit-web-search" in names

    def test_t2_rules_included_when_selected(self):
        result = build_policy_dict(["block-catastrophic-deletion", "block-ssh-key-access"])
        names = [p["name"] for p in result["policies"]]
        assert "block-catastrophic-deletion" in names
        assert "block-ssh-key-access" in names

    def test_selected_in_catalog_order(self):
        # rate-limit-web-search comes after block-dangerous-shell in catalog
        result = build_policy_dict(["rate-limit-web-search", "block-dangerous-shell"])
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
        result = build_policy_dict(["block-dangerous-shell"], extra_rules=extra)
        names = [p["name"] for p in result["policies"]]
        shell_idx = names.index("block-dangerous-shell")
        scan_idx = names.index("scan-env")
        assert scan_idx > shell_idx

    def test_validates_as_policy_config(self):
        result = build_policy_dict(get_optional_rule_ids())
        PolicyConfig.model_validate(result)

    def test_deepcopy_prevents_mutation(self):
        """Calling build_policy_dict should not mutate the original rule_data."""
        original_rule = get_rule_by_id("rate-limit-web-search")
        assert original_rule is not None
        original_max = original_rule.rule_data["rate_limit"]["max_calls"]

        result = build_policy_dict(["rate-limit-web-search"])
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
        assert "block-catastrophic-shell" in output
        assert "block-catastrophic-sql-shell" in output
        assert "block-catastrophic-sql-db" in output

    def test_header_includes_selected_ids(self):
        output = generate_yaml(["block-dangerous-shell", "rate-limit-web-search"])
        assert "Selected rules: block-dangerous-shell, rate-limit-web-search" in output

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
        output = generate_yaml(["block-dangerous-shell"], extra_rules=extra)
        parsed = yaml.safe_load(output)
        names = [p["name"] for p in parsed["policies"]]
        assert "custom-rule" in names


class TestT3Rules:
    """T3 command-parsing rules have correct structure."""

    def test_t3_rules_count(self):
        t3_rules = [r for r in ALL_RULES if r.tier == 3]
        assert len(t3_rules) == 3

    def test_t3_rules_have_args_match(self):
        """All tier=3 rules use args_match conditions."""
        t3_rules = [r for r in ALL_RULES if r.tier == 3]
        for rule in t3_rules:
            conditions = rule.rule_data.get("conditions", {})
            assert "args_match" in conditions, f"T3 rule {rule.id} lacks args_match"

    def test_t3_rules_are_default_on(self):
        t3_rules = [r for r in ALL_RULES if r.tier == 3]
        for rule in t3_rules:
            assert rule.default_on, f"T3 rule {rule.id} should be default_on"

    def test_t3_rule_ids(self):
        t3_ids = {r.id for r in ALL_RULES if r.tier == 3}
        assert t3_ids == {
            "detect-command-chaining",
            "detect-obfuscation",
            "detect-pipe-to-shell",
        }

    def test_t3_rules_generate_valid_yaml(self):
        """generate_yaml() with T3 rules produces valid PolicyConfig."""
        t3_ids = [r.id for r in ALL_RULES if r.tier == 3]
        output = generate_yaml(t3_ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_t3_rules_included_in_build_policy_dict(self):
        result = build_policy_dict(["detect-command-chaining", "detect-pipe-to-shell"])
        names = [p["name"] for p in result["policies"]]
        assert "detect-command-chaining" in names
        assert "detect-pipe-to-shell" in names

    def test_t3_rules_in_default_on_ids(self):
        defaults = get_default_on_ids()
        assert "detect-command-chaining" in defaults
        assert "detect-obfuscation" in defaults
        assert "detect-pipe-to-shell" in defaults

    def test_t3_rule_lookup(self):
        rule = get_rule_by_id("detect-command-chaining")
        assert rule is not None
        assert rule.tier == 3


class TestT4Rules:
    """T4 cross-call correlation rules have correct structure."""

    def test_t4_rules_count(self):
        t4_rules = [r for r in ALL_RULES if r.tier == 4]
        assert len(t4_rules) == 3

    def test_t4_rule_ids(self):
        t4_ids = {r.id for r in ALL_RULES if r.tier == 4}
        assert t4_ids == {
            "detect-encode-transmit",
            "detect-behavioral-anomaly",
            "block-clipboard-exfil",
        }

    def test_t4_encode_transmit_is_default_on(self):
        rule = get_rule_by_id("detect-encode-transmit")
        assert rule is not None
        assert rule.default_on is True

    def test_t4_behavioral_anomaly_is_default_off(self):
        rule = get_rule_by_id("detect-behavioral-anomaly")
        assert rule is not None
        assert rule.default_on is False

    def test_t4_clipboard_exfil_is_default_off(self):
        rule = get_rule_by_id("block-clipboard-exfil")
        assert rule is not None
        assert rule.default_on is False

    def test_t4_rules_generate_valid_yaml(self):
        """generate_yaml() with T4 rules produces valid PolicyConfig."""
        t4_ids = [r.id for r in ALL_RULES if r.tier == 4]
        output = generate_yaml(t4_ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_t4_rules_included_in_build_policy_dict(self):
        result = build_policy_dict(["detect-encode-transmit", "block-clipboard-exfil"])
        names = [p["name"] for p in result["policies"]]
        assert "detect-encode-transmit" in names
        assert "block-clipboard-exfil" in names

    def test_t4_encode_transmit_in_default_on_ids(self):
        defaults = get_default_on_ids()
        assert "detect-encode-transmit" in defaults

    def test_t4_rule_lookup(self):
        rule = get_rule_by_id("detect-encode-transmit")
        assert rule is not None
        assert rule.tier == 4


class TestT5Rules:
    """T5 content-scanning rules have correct structure."""

    def test_t5_rules_count(self):
        t5_rules = [r for r in ALL_RULES if r.tier == 5]
        assert len(t5_rules) == 2

    def test_t5_rules_have_content_scan(self):
        """All tier=5 rules use content_scan conditions."""
        t5_rules = [r for r in ALL_RULES if r.tier == 5]
        for rule in t5_rules:
            conditions = rule.rule_data.get("conditions", {})
            assert "content_scan" in conditions, f"T5 rule {rule.id} lacks content_scan"

    def test_t5_rule_ids(self):
        t5_ids = {r.id for r in ALL_RULES if r.tier == 5}
        assert t5_ids == {
            "detect-secrets-outbound",
            "detect-prompt-injection",
        }

    def test_t5_rules_generate_valid_yaml(self):
        """generate_yaml() with T5 rules produces valid PolicyConfig."""
        t5_ids = [r.id for r in ALL_RULES if r.tier == 5]
        output = generate_yaml(t5_ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_t5_rules_included_in_build_policy_dict(self):
        result = build_policy_dict(["detect-secrets-outbound", "detect-prompt-injection"])
        names = [p["name"] for p in result["policies"]]
        assert "detect-secrets-outbound" in names
        assert "detect-prompt-injection" in names

    def test_t5_secrets_is_default_on(self):
        rule = get_rule_by_id("detect-secrets-outbound")
        assert rule is not None
        assert rule.default_on is True

    def test_t5_injection_is_default_off(self):
        rule = get_rule_by_id("detect-prompt-injection")
        assert rule is not None
        assert rule.default_on is False

    def test_t5_rule_lookup(self):
        rule = get_rule_by_id("detect-secrets-outbound")
        assert rule is not None
        assert rule.tier == 5


class TestGetOptionalRulesByCategory:
    """Category grouping helper returns correct structure."""

    def test_returns_all_optional_rules(self):
        grouped = get_optional_rules_by_category()
        total = sum(len(rules) for rules in grouped.values())
        assert total == 81

    def test_categories_in_display_order(self):
        grouped = get_optional_rules_by_category()
        assert list(grouped.keys()) == list(CATEGORY_DISPLAY.keys())

    def test_all_categories_nonempty(self):
        grouped = get_optional_rules_by_category()
        for key, rules in grouped.items():
            assert len(rules) > 0, f"Category {key!r} is empty"


class TestFilesystemExtraRules:
    """Filesystem Protection extra rules."""

    def test_count(self):
        ids = {
            "block-destructive-disk-ops",
            "block-device-writes",
            "require-safe-delete",
            "block-fork-bombs",
        }
        found = [r for r in ALL_RULES if r.id in ids]
        assert len(found) == 4

    def test_rule_ids(self):
        ids = {r.id for r in ALL_RULES if r.category == "filesystem"}
        for expected in [
            "block-destructive-disk-ops",
            "block-device-writes",
            "require-safe-delete",
            "block-fork-bombs",
        ]:
            assert expected in ids

    def test_valid_yaml(self):
        ids = [
            "block-destructive-disk-ops",
            "block-device-writes",
            "require-safe-delete",
            "block-fork-bombs",
        ]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-destructive-disk-ops" in defaults
        assert "block-device-writes" in defaults
        assert "block-fork-bombs" in defaults
        assert "require-safe-delete" not in defaults


class TestShellExtraRules:
    """Shell Safety extra rules."""

    def test_count(self):
        ids = {
            "block-privilege-escalation",
            "block-permission-changes",
            "block-pipe-to-shell",
            "block-critical-process-kill",
            "limit-command-timeout",
        }
        found = [r for r in ALL_RULES if r.id in ids]
        assert len(found) == 5

    def test_rule_ids(self):
        for expected in [
            "block-privilege-escalation",
            "block-permission-changes",
            "block-pipe-to-shell",
            "block-critical-process-kill",
            "limit-command-timeout",
        ]:
            rule = get_rule_by_id(expected)
            assert rule is not None, f"Missing rule: {expected}"
            assert rule.category == "shell"

    def test_valid_yaml(self):
        ids = [
            "block-privilege-escalation",
            "block-permission-changes",
            "block-pipe-to-shell",
            "block-critical-process-kill",
            "limit-command-timeout",
        ]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-privilege-escalation" in defaults
        assert "block-permission-changes" in defaults
        assert "block-pipe-to-shell" in defaults
        assert "block-critical-process-kill" in defaults
        assert "limit-command-timeout" not in defaults


class TestDbExtraRules:
    """Database Safety extra rules."""

    def test_count(self):
        ids = {"block-unqualified-dml", "block-db-permission-changes"}
        found = [r for r in ALL_RULES if r.id in ids]
        assert len(found) == 2

    def test_valid_yaml(self):
        output = generate_yaml(["block-unqualified-dml", "block-db-permission-changes"])
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-unqualified-dml" in defaults
        assert "block-db-permission-changes" not in defaults


class TestVcsRules:
    """Version Control rules."""

    def test_count(self):
        vcs = [r for r in ALL_RULES if r.category == "vcs"]
        assert len(vcs) == 3

    def test_rule_ids(self):
        vcs_ids = {r.id for r in ALL_RULES if r.category == "vcs"}
        assert vcs_ids == {
            "block-force-push",
            "block-branch-deletion",
            "detect-credential-commit",
        }

    def test_valid_yaml(self):
        ids = ["block-force-push", "block-branch-deletion", "detect-credential-commit"]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_all_default_on(self):
        defaults = get_default_on_ids()
        for rule_id in ["block-force-push", "block-branch-deletion", "detect-credential-commit"]:
            assert rule_id in defaults


class TestSupplyChainRules:
    """Supply Chain rules."""

    def test_count(self):
        sc = [r for r in ALL_RULES if r.category == "supply-chain"]
        assert len(sc) == 2

    def test_rule_ids(self):
        sc_ids = {r.id for r in ALL_RULES if r.category == "supply-chain"}
        assert sc_ids == {"block-registry-manipulation", "flag-postinstall-scripts"}

    def test_valid_yaml(self):
        output = generate_yaml(["block-registry-manipulation", "flag-postinstall-scripts"])
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-registry-manipulation" in defaults
        assert "flag-postinstall-scripts" not in defaults


class TestNetworkRules:
    """Network & Exfiltration rules."""

    def test_count(self):
        net = [r for r in ALL_RULES if r.category == "network"]
        assert len(net) == 8  # 6 new + detect-encode-transmit + block-clipboard-exfil

    def test_rule_ids(self):
        net_ids = {r.id for r in ALL_RULES if r.category == "network"}
        for expected in [
            "restrict-outbound-http",
            "block-dns-exfiltration",
            "block-ssh-unknown-hosts",
            "block-port-binding",
            "block-firewall-changes",
            "block-browser-data-access",
            "detect-encode-transmit",
            "block-clipboard-exfil",
        ]:
            assert expected in net_ids

    def test_valid_yaml(self):
        ids = [
            "restrict-outbound-http",
            "block-dns-exfiltration",
            "block-ssh-unknown-hosts",
            "block-port-binding",
            "block-firewall-changes",
            "block-browser-data-access",
        ]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-dns-exfiltration" in defaults
        assert "block-ssh-unknown-hosts" in defaults
        assert "block-firewall-changes" in defaults
        assert "block-browser-data-access" in defaults
        assert "restrict-outbound-http" not in defaults
        assert "block-port-binding" not in defaults


class TestCloudRules:
    """Cloud & Infrastructure rules."""

    def test_count(self):
        cloud = [r for r in ALL_RULES if r.category == "cloud"]
        assert len(cloud) == 6

    def test_rule_ids(self):
        cloud_ids = {r.id for r in ALL_RULES if r.category == "cloud"}
        assert cloud_ids == {
            "block-cloud-resource-deletion",
            "block-iam-changes",
            "block-backup-deletion",
            "block-destructive-docker",
            "block-container-escape",
            "block-k8s-destruction",
        }

    def test_valid_yaml(self):
        ids = [
            "block-cloud-resource-deletion",
            "block-iam-changes",
            "block-backup-deletion",
            "block-destructive-docker",
            "block-container-escape",
            "block-k8s-destruction",
        ]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "block-cloud-resource-deletion" in defaults
        assert "block-backup-deletion" in defaults
        assert "block-destructive-docker" in defaults
        assert "block-container-escape" in defaults
        assert "block-iam-changes" not in defaults
        assert "block-k8s-destruction" not in defaults


class TestAgentRules:
    """AI Agent Safety rules."""

    def test_count(self):
        agent = [r for r in ALL_RULES if r.category == "agent"]
        assert len(agent) == 5  # 3 new + detect-behavioral-anomaly + detect-prompt-injection

    def test_rule_ids(self):
        agent_ids = {r.id for r in ALL_RULES if r.category == "agent"}
        for expected in [
            "detect-mcp-tool-poisoning",
            "block-agent-self-modification",
            "rate-limit-tool-calls",
            "detect-behavioral-anomaly",
            "detect-prompt-injection",
        ]:
            assert expected in agent_ids

    def test_valid_yaml(self):
        ids = [
            "detect-mcp-tool-poisoning",
            "block-agent-self-modification",
            "rate-limit-tool-calls",
        ]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_default_on_correctness(self):
        defaults = get_default_on_ids()
        assert "detect-mcp-tool-poisoning" in defaults
        assert "block-agent-self-modification" in defaults
        assert "rate-limit-tool-calls" in defaults


class TestOsRules:
    """OS Hardening rules (macOS + Linux + Windows)."""

    def test_count(self):
        os_rules = [r for r in ALL_RULES if r.category == "os"]
        assert len(os_rules) == 16  # 5 macOS + 3 Linux + 8 Windows

    def test_macos_rule_ids(self):
        os_ids = {r.id for r in ALL_RULES if r.category == "os"}
        for expected in [
            "block-sip-changes",
            "block-tcc-manipulation",
            "block-gatekeeper-bypass",
            "block-osascript-abuse",
            "block-defaults-security",
        ]:
            assert expected in os_ids

    def test_linux_rule_ids(self):
        os_ids = {r.id for r in ALL_RULES if r.category == "os"}
        for expected in [
            "block-library-injection",
            "block-mac-disablement",
            "block-kernel-modification",
        ]:
            assert expected in os_ids

    def test_windows_rule_ids(self):
        os_ids = {r.id for r in ALL_RULES if r.category == "os"}
        for expected in [
            "block-defender-manipulation",
            "block-shadow-copy-deletion",
            "block-boot-config-changes",
            "block-uac-bypass",
            "block-powershell-cradles",
            "block-event-log-clearing",
            "block-lsass-sam-access",
            "block-hidden-accounts",
        ]:
            assert expected in os_ids

    def test_valid_yaml(self):
        ids = [r.id for r in ALL_RULES if r.category == "os"]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)

    def test_all_default_on(self):
        defaults = get_default_on_ids()
        os_rules = [r for r in ALL_RULES if r.category == "os"]
        for rule in os_rules:
            assert rule.id in defaults, f"OS rule {rule.id} should be default_on"


class TestSecretsExtraRules:
    """Secrets & Credentials extra rules."""

    def test_count(self):
        ids = {"block-credential-stores", "block-path-poisoning", "block-env-secret-exposure"}
        found = [r for r in ALL_RULES if r.id in ids]
        assert len(found) == 3

    def test_all_default_on(self):
        defaults = get_default_on_ids()
        for rule_id in [
            "block-credential-stores",
            "block-path-poisoning",
            "block-env-secret-exposure",
        ]:
            assert rule_id in defaults

    def test_valid_yaml(self):
        ids = ["block-credential-stores", "block-path-poisoning", "block-env-secret-exposure"]
        output = generate_yaml(ids)
        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)
