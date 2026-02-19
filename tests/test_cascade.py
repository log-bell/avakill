"""Tests for multi-level policy cascade."""

from pathlib import Path

import pytest

from avakill.core.cascade import PolicyCascade
from avakill.core.exceptions import ConfigError
from avakill.core.models import PolicyConfig, PolicyRule, RateLimit


def _write_policy(path: Path, content: str) -> Path:
    """Write a YAML policy file and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _simple_policy_yaml(
    default_action: str = "deny",
    rules: list[dict] | None = None,
) -> str:
    """Generate a simple YAML policy string."""
    import yaml

    data: dict = {"version": "1.0", "default_action": default_action, "policies": rules or []}
    return yaml.dump(data)


class TestPolicyCascadeDiscover:
    """Tests for PolicyCascade.discover()."""

    def test_discovers_project_level_avakill_yaml(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "avakill.yaml", _simple_policy_yaml())
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        levels = [level for level, _ in found]
        assert "project" in levels

    def test_discovers_project_level_dot_avakill(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / ".avakill" / "policy.yaml", _simple_policy_yaml())
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        levels = [level for level, _ in found]
        assert "project" in levels

    def test_discovers_legacy_avakill_yml(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "avakill.yml", _simple_policy_yaml())
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        assert any(level == "project" for level, _ in found)

    def test_discovers_local_override(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "avakill.yaml", _simple_policy_yaml())
        _write_policy(tmp_path / ".avakill" / "policy.local.yaml", _simple_policy_yaml())
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        levels = [level for level, _ in found]
        assert "local" in levels

    def test_missing_levels_skipped(self, tmp_path: Path) -> None:
        # No policy files at all in tmp_path
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        # System and global may or may not exist on the host,
        # but project and local should be missing
        project_local = [level for level, _ in found if level in ("project", "local")]
        assert project_local == []

    def test_walks_up_parent_directories(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "avakill.yaml", _simple_policy_yaml())
        child = tmp_path / "sub" / "dir"
        child.mkdir(parents=True)
        cascade = PolicyCascade()
        found = cascade.discover(cwd=child)
        assert any(level == "project" for level, _ in found)

    def test_dot_avakill_preferred_over_avakill_yaml(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / ".avakill" / "policy.yaml", _simple_policy_yaml())
        _write_policy(tmp_path / "avakill.yaml", _simple_policy_yaml())
        cascade = PolicyCascade()
        found = cascade.discover(cwd=tmp_path)
        project_paths = [p for level, p in found if level == "project"]
        assert len(project_paths) == 1
        assert ".avakill" in str(project_paths[0])


class TestPolicyCascadeMerge:
    """Tests for PolicyCascade.merge()."""

    def test_deny_accumulates(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="block-shell", tools=["shell_execute"], action="deny"),
            ],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="block-write", tools=["file_write"], action="deny"),
            ],
        )
        merged = PolicyCascade.merge([c1, c2])
        deny_names = [r.name for r in merged.policies if r.action == "deny"]
        assert "block-shell" in deny_names
        assert "block-write" in deny_names

    def test_default_action_deny_wins(self) -> None:
        c1 = PolicyConfig(version="1.0", default_action="allow", policies=[])
        c2 = PolicyConfig(version="1.0", default_action="deny", policies=[])
        merged = PolicyCascade.merge([c1, c2])
        assert merged.default_action == "deny"

    def test_default_action_all_allow(self) -> None:
        c1 = PolicyConfig(version="1.0", default_action="allow", policies=[])
        c2 = PolicyConfig(version="1.0", default_action="allow", policies=[])
        merged = PolicyCascade.merge([c1, c2])
        assert merged.default_action == "allow"

    def test_rate_limit_most_restrictive_wins(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="rate-search",
                    tools=["web_search"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=10, window="60s"),
                ),
            ],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="rate-search-strict",
                    tools=["web_search"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=5, window="60s"),
                ),
            ],
        )
        merged = PolicyCascade.merge([c1, c2])
        rate_rules = [r for r in merged.policies if r.rate_limit is not None]
        assert len(rate_rules) >= 1
        # The most restrictive (5) should be present
        min_calls = min(r.rate_limit.max_calls for r in rate_rules)
        assert min_calls == 5

    def test_hard_deny_cannot_be_relaxed(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="block-shell",
                    tools=["shell_execute"],
                    action="deny",
                    enforcement="hard",
                ),
            ],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="allow-shell",
                    tools=["shell_execute"],
                    action="allow",
                ),
            ],
        )
        merged = PolicyCascade.merge([c1, c2])
        # The hard deny should be present, and the allow should be removed
        shell_rules = [r for r in merged.policies if "shell_execute" in r.tools]
        allow_rules = [r for r in shell_rules if r.action == "allow"]
        deny_rules = [r for r in shell_rules if r.action == "deny"]
        assert len(deny_rules) == 1
        assert len(allow_rules) == 0

    def test_soft_deny_can_be_relaxed(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="block-shell-soft",
                    tools=["shell_execute"],
                    action="deny",
                    enforcement="soft",
                ),
            ],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="allow-shell",
                    tools=["shell_execute"],
                    action="allow",
                ),
            ],
        )
        merged = PolicyCascade.merge([c1, c2])
        # Soft deny doesn't add to hard_denied_patterns, so allow is kept
        shell_rules = [r for r in merged.policies if "shell_execute" in r.tools]
        allow_rules = [r for r in shell_rules if r.action == "allow"]
        assert len(allow_rules) == 1

    def test_merge_empty_list_returns_default(self) -> None:
        merged = PolicyCascade.merge([])
        assert merged.default_action == "deny"
        assert merged.policies == []

    def test_merge_single_config_returns_copy(self) -> None:
        original = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="r1", tools=["t1"], action="allow"),
            ],
        )
        merged = PolicyCascade.merge([original])
        assert merged.default_action == "allow"
        assert len(merged.policies) == 1
        assert merged.policies[0].name == "r1"
        # Verify it's a copy, not the same object
        assert merged is not original

    def test_duplicate_rule_names_first_wins(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[PolicyRule(name="my-rule", tools=["t1"], action="deny")],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[PolicyRule(name="my-rule", tools=["t2"], action="allow")],
        )
        merged = PolicyCascade.merge([c1, c2])
        my_rules = [r for r in merged.policies if r.name == "my-rule"]
        assert len(my_rules) == 1
        assert my_rules[0].action == "deny"  # first wins

    def test_require_approval_rules_kept(self) -> None:
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="ask-write", tools=["file_write"], action="require_approval"),
            ],
        )
        merged = PolicyCascade.merge([c1])
        assert any(r.action == "require_approval" for r in merged.policies)

    def test_hard_deny_glob_blocks_specific_allow(self) -> None:
        """A hard deny with glob pattern 'file_*' should block a specific allow 'file_write'."""
        c1 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="block-all-file",
                    tools=["file_*"],
                    action="deny",
                    enforcement="hard",
                ),
            ],
        )
        c2 = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="allow-file-write",
                    tools=["file_write"],
                    action="allow",
                ),
            ],
        )
        merged = PolicyCascade.merge([c1, c2])
        allow_rules = [r for r in merged.policies if r.action == "allow"]
        assert len(allow_rules) == 0, "Allow 'file_write' should be blocked by hard deny 'file_*'"


class TestPolicyCascadeLoad:
    """Tests for PolicyCascade.load()."""

    def test_load_single_project_file(self, tmp_path: Path) -> None:
        _write_policy(
            tmp_path / "avakill.yaml",
            _simple_policy_yaml(
                rules=[{"name": "allow-read", "tools": ["file_read"], "action": "allow"}]
            ),
        )
        cascade = PolicyCascade()
        config = cascade.load(cwd=tmp_path)
        assert len(config.policies) == 1
        assert config.policies[0].name == "allow-read"

    def test_load_merges_project_and_local(self, tmp_path: Path) -> None:
        _write_policy(
            tmp_path / "avakill.yaml",
            _simple_policy_yaml(
                rules=[{"name": "allow-read", "tools": ["file_read"], "action": "allow"}]
            ),
        )
        _write_policy(
            tmp_path / ".avakill" / "policy.local.yaml",
            _simple_policy_yaml(
                rules=[{"name": "block-shell", "tools": ["shell_execute"], "action": "deny"}]
            ),
        )
        cascade = PolicyCascade()
        config = cascade.load(cwd=tmp_path)
        names = [r.name for r in config.policies]
        assert "allow-read" in names
        assert "block-shell" in names

    def test_load_no_files_raises_config_error(self, tmp_path: Path) -> None:
        cascade = PolicyCascade()
        with pytest.raises(ConfigError, match="No policy files found"):
            cascade.load(cwd=tmp_path)

    def test_load_invalid_yaml_raises_config_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "avakill.yaml"
        bad.write_text("{ invalid yaml ::::")
        cascade = PolicyCascade()
        with pytest.raises(ConfigError, match="Invalid YAML"):
            cascade.load(cwd=tmp_path)

    def test_load_invalid_policy_raises_config_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "avakill.yaml"
        bad.write_text("version: '2.0'\ndefault_action: deny\npolicies: []\n")
        cascade = PolicyCascade()
        with pytest.raises(ConfigError, match="Invalid policy"):
            cascade.load(cwd=tmp_path)
