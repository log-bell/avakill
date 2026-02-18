"""Tests for the Landlock filesystem enforcer."""

import sys

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.landlock import (
    LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_MAKE_DIR,
    LANDLOCK_ACCESS_FS_MAKE_REG,
    LANDLOCK_ACCESS_FS_MAKE_SYM,
    LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_WRITE_FILE,
    LandlockEnforcer,
)


def _deny_policy(*tools: str) -> PolicyConfig:
    """Create a policy that denies the given tools."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="deny-tools", tools=list(tools), action="deny"),
        ],
    )


def _empty_policy() -> PolicyConfig:
    """Create a policy with no deny rules."""
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-all", tools=["*"], action="allow"),
        ],
    )


class TestLandlockEnforcer:
    """Tests for LandlockEnforcer.available() and generate_ruleset()."""

    def test_available_returns_bool(self) -> None:
        result = LandlockEnforcer.available()
        assert isinstance(result, bool)

    def test_available_false_on_non_linux(self) -> None:
        if sys.platform != "linux":
            assert LandlockEnforcer.available() is False

    def test_generate_ruleset_from_deny_rules(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("file_write", "shell_execute")
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["landlock_abi"] == 1
        assert ruleset["handled_access_fs"] != 0
        assert len(ruleset["sources"]) == 2
        assert len(ruleset["restricted_flag_names"]) > 0

    def test_generate_ruleset_empty_policy(self) -> None:
        enforcer = LandlockEnforcer()
        config = _empty_policy()
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["handled_access_fs"] == 0
        assert ruleset["sources"] == []
        assert ruleset["restricted_flag_names"] == []

    def test_generate_ruleset_maps_file_write_to_write_file_access(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("file_write")
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_WRITE_FILE
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_MAKE_REG
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_MAKE_DIR
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_MAKE_SYM
        assert "WRITE_FILE" in ruleset["restricted_flag_names"]

    def test_generate_ruleset_maps_file_delete(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("file_delete")
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_REMOVE_FILE
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_REMOVE_DIR

    def test_generate_ruleset_maps_shell_execute(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("shell_execute")
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_EXECUTE
        assert "EXECUTE" in ruleset["restricted_flag_names"]

    def test_generate_ruleset_wildcard_deny(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("*")
        ruleset = enforcer.generate_ruleset(config)

        # Wildcard should restrict all filesystem access
        assert ruleset["handled_access_fs"] != 0
        assert len(ruleset["restricted_flag_names"]) > 5

    def test_generate_ruleset_glob_pattern(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("file_*")
        ruleset = enforcer.generate_ruleset(config)

        # Should match file_write, file_delete, file_edit
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_WRITE_FILE
        assert ruleset["handled_access_fs"] & LANDLOCK_ACCESS_FS_REMOVE_FILE

    def test_generate_ruleset_unknown_tool_ignored(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("unknown_tool")
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["handled_access_fs"] == 0
        assert ruleset["sources"] == []

    def test_generate_ruleset_source_tracks_rule_name(self) -> None:
        enforcer = LandlockEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="my-rule", tools=["file_write"], action="deny"),
            ],
        )
        ruleset = enforcer.generate_ruleset(config)

        assert ruleset["sources"][0]["rule"] == "my-rule"
        assert ruleset["sources"][0]["tool_pattern"] == "file_write"

    def test_generate_ruleset_skips_allow_rules(self) -> None:
        enforcer = LandlockEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
        )
        ruleset = enforcer.generate_ruleset(config)

        assert len(ruleset["sources"]) == 1
        assert ruleset["sources"][0]["rule"] == "deny-write"


class TestLandlockApply:
    """Tests for LandlockEnforcer.apply() — platform-conditional."""

    @pytest.mark.skipif(
        sys.platform != "linux" or not LandlockEnforcer.available(),
        reason="Landlock required",
    )
    def test_apply_runs_on_linux_with_landlock(self, tmp_path) -> None:
        enforcer = LandlockEnforcer()
        # Verify the method exists and is callable.
        # Actually applying would restrict the test runner process,
        # so we don't call apply() here.
        assert callable(enforcer.apply)

    @pytest.mark.skipif(sys.platform == "linux", reason="Non-Linux test")
    def test_apply_raises_on_non_linux(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("file_write")
        with pytest.raises(RuntimeError, match="not available"):
            enforcer.apply(config)
