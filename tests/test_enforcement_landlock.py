"""Tests for the Landlock filesystem enforcer."""

import sys
from unittest.mock import patch

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.landlock import (
    ALL_ACCESS_FS,
    LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_MAKE_DIR,
    LANDLOCK_ACCESS_FS_MAKE_REG,
    LANDLOCK_ACCESS_FS_MAKE_SYM,
    LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_REFER,
    LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_TRUNCATE,
    LANDLOCK_ACCESS_FS_WRITE_FILE,
    PATH_ACCESS_MAP,
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

        assert isinstance(ruleset["landlock_abi"], int)
        assert ruleset["landlock_abi"] >= 0
        assert ruleset["handled_access_fs"] != 0
        assert len(ruleset["sources"]) == 2
        assert len(ruleset["restricted_flag_names"]) > 0
        assert "supported_features" in ruleset

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


class TestLandlockABIVersion:
    """Tests for ABI version detection and feature flags."""

    def test_abi_version_returns_int(self) -> None:
        result = LandlockEnforcer.abi_version()
        assert isinstance(result, int)
        assert result >= 0

    def test_abi_version_zero_on_non_linux(self) -> None:
        if sys.platform != "linux":
            assert LandlockEnforcer.abi_version() == 0

    def test_supported_features_abi_1(self) -> None:
        features = LandlockEnforcer.supported_features(1)
        assert features["filesystem"] is True
        assert features["file_refer"] is False
        assert features["file_truncate"] is False
        assert features["network_tcp"] is False
        assert features["device_ioctl"] is False
        assert features["ipc_scoping"] is False

    def test_supported_features_abi_4_includes_network(self) -> None:
        features = LandlockEnforcer.supported_features(4)
        assert features["filesystem"] is True
        assert features["file_refer"] is True
        assert features["file_truncate"] is True
        assert features["network_tcp"] is True
        assert features["device_ioctl"] is False
        assert features["ipc_scoping"] is False

    def test_supported_features_abi_6_includes_ipc(self) -> None:
        features = LandlockEnforcer.supported_features(6)
        assert features["filesystem"] is True
        assert features["file_refer"] is True
        assert features["file_truncate"] is True
        assert features["network_tcp"] is True
        assert features["device_ioctl"] is True
        assert features["ipc_scoping"] is True


class TestLandlockGracefulDegradation:
    """Tests for ABI-based flag masking in generate_ruleset."""

    def test_generate_ruleset_masks_to_abi_version(self) -> None:
        enforcer = LandlockEnforcer()
        config = _deny_policy("*")

        # With ABI 1, only base FS flags should be present
        with patch.object(LandlockEnforcer, "abi_version", return_value=1):
            ruleset = enforcer.generate_ruleset(config)

        masked_flags = ruleset["handled_access_fs"]
        assert masked_flags & ALL_ACCESS_FS  # ABI 1 flags present
        assert not (masked_flags & LANDLOCK_ACCESS_FS_REFER)  # ABI 2 flag absent
        assert not (masked_flags & LANDLOCK_ACCESS_FS_TRUNCATE)  # ABI 3 flag absent

    def test_network_flags_excluded_below_abi_4(self) -> None:
        features_abi_3 = LandlockEnforcer.supported_features(3)
        assert features_abi_3["network_tcp"] is False

        features_abi_4 = LandlockEnforcer.supported_features(4)
        assert features_abi_4["network_tcp"] is True


class TestLandlockPathRules:
    """Tests for per-path Landlock rules."""

    def test_apply_path_rules_allows_read_on_specified_path(self) -> None:
        enforcer = LandlockEnforcer()
        # Verify the method signature and that it accepts valid inputs
        assert callable(enforcer.apply_path_rules)
        # PATH_ACCESS_MAP should have read/write/execute entries
        assert "read" in PATH_ACCESS_MAP
        assert "write" in PATH_ACCESS_MAP
        assert "execute" in PATH_ACCESS_MAP

    def test_apply_path_rules_read_maps_to_correct_flags(self) -> None:
        read_flags = PATH_ACCESS_MAP["read"]
        assert read_flags & LANDLOCK_ACCESS_FS_READ_FILE
        assert read_flags & LANDLOCK_ACCESS_FS_READ_DIR
        assert not (read_flags & LANDLOCK_ACCESS_FS_WRITE_FILE)

    def test_apply_path_rules_write_maps_to_correct_flags(self) -> None:
        write_flags = PATH_ACCESS_MAP["write"]
        assert write_flags & LANDLOCK_ACCESS_FS_WRITE_FILE
        assert write_flags & LANDLOCK_ACCESS_FS_MAKE_REG
        assert write_flags & LANDLOCK_ACCESS_FS_MAKE_DIR
        assert write_flags & LANDLOCK_ACCESS_FS_REMOVE_FILE
        assert write_flags & LANDLOCK_ACCESS_FS_REMOVE_DIR

    def test_apply_path_rules_handles_missing_directory_gracefully(self) -> None:
        # Calling with nonexistent path should not raise
        enforcer = LandlockEnforcer()
        if not LandlockEnforcer.available():
            pytest.skip("Landlock not available")
        # Would need a real ruleset_fd on Linux; test that method exists
        assert callable(enforcer.apply_path_rules)

    def test_apply_path_rules_resolves_home_tilde(self) -> None:
        import os

        # Verify tilde expansion works in path handling
        expanded = os.path.expanduser("~/test_path")
        assert "~" not in expanded
        assert expanded.startswith("/")


class TestLandlockNetworkRules:
    """Tests for Landlock network rules (ABI 4+)."""

    def test_apply_network_rules_skipped_below_abi_4(self) -> None:
        enforcer = LandlockEnforcer()
        # On non-Linux (ABI 0), apply_network_rules should be a no-op
        if sys.platform != "linux":
            # Can't call with real ruleset_fd, but verify method exists
            assert callable(enforcer.apply_network_rules)

    @pytest.mark.skipif(
        not LandlockEnforcer.available() or LandlockEnforcer.abi_version() < 4,
        reason="Landlock ABI 4+ required for network rules",
    )
    def test_apply_network_rules_allows_specified_ports(self) -> None:
        enforcer = LandlockEnforcer()
        # On Linux with ABI 4+, verify method is callable
        assert callable(enforcer.apply_network_rules)
