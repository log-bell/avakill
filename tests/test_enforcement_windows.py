"""Tests for the Windows process restriction enforcer."""

import sys

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.windows import (
    TOOL_TO_WINDOWS_ACTIONS,
    WindowsEnforcer,
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


class TestWindowsEnforcer:
    """Tests for WindowsEnforcer.available() and generate_report()."""

    def test_available_returns_bool(self) -> None:
        result = WindowsEnforcer.available()
        assert isinstance(result, bool)

    def test_available_false_on_non_windows(self) -> None:
        if sys.platform != "win32":
            assert WindowsEnforcer.available() is False

    def test_generate_report_from_deny_rules(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("file_write", "shell_execute")
        report = enforcer.generate_report(config)

        assert report["platform"] == "windows"
        assert report["job_object"] is True
        assert len(report["privileges_removed"]) > 0
        assert len(report["sources"]) == 2

    def test_generate_report_empty_policy(self) -> None:
        enforcer = WindowsEnforcer()
        config = _empty_policy()
        report = enforcer.generate_report(config)

        assert report["job_object"] is False
        assert report["privileges_removed"] == []
        assert report["sources"] == []

    def test_generate_report_maps_file_write(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("file_write")
        report = enforcer.generate_report(config)

        assert "remove_SeRestorePrivilege" in report["actions"]
        assert "SeRestorePrivilege" in report["privileges_removed"]

    def test_generate_report_maps_shell_execute(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("shell_execute")
        report = enforcer.generate_report(config)

        assert "job_limit_children" in report["actions"]
        assert "remove_SeDebugPrivilege" in report["actions"]

    def test_generate_report_wildcard_deny(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("*")
        report = enforcer.generate_report(config)

        assert report["job_object"] is True
        assert len(report["privileges_removed"]) >= 4
        assert len(report["actions"]) > 0

    def test_generate_report_glob_pattern(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("file_*")
        report = enforcer.generate_report(config)

        # Should match file_write, file_delete, file_edit
        assert "remove_SeRestorePrivilege" in report["actions"]

    def test_generate_report_unknown_tool_ignored(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("unknown_tool")
        report = enforcer.generate_report(config)

        # Unknown tool has no mapped actions, but privileges still removed
        # because deny rules exist
        assert report["sources"] == []
        assert report["privileges_removed"] == []

    def test_generate_report_source_tracks_rule_name(self) -> None:
        enforcer = WindowsEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="my-rule", tools=["file_write"], action="deny"),
            ],
        )
        report = enforcer.generate_report(config)

        assert report["sources"][0]["rule"] == "my-rule"
        assert report["sources"][0]["tool_pattern"] == "file_write"

    def test_generate_report_skips_allow_rules(self) -> None:
        enforcer = WindowsEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
        )
        report = enforcer.generate_report(config)

        assert len(report["sources"]) == 1
        assert report["sources"][0]["rule"] == "deny-write"

    def test_all_dangerous_privileges_included(self) -> None:
        """When any deny rule matches, all dangerous privileges are marked for removal."""
        enforcer = WindowsEnforcer()
        config = _deny_policy("file_write")
        report = enforcer.generate_report(config)

        expected = {
            "SeBackupPrivilege",
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
        }
        assert set(report["privileges_removed"]) == expected

    def test_tool_action_mapping_complete(self) -> None:
        """Verify all mapped tools have non-empty action lists."""
        for tool, actions in TOOL_TO_WINDOWS_ACTIONS.items():
            assert len(actions) > 0, f"Tool {tool} has empty actions"


class TestWindowsApply:
    """Tests for WindowsEnforcer.apply() — platform-conditional."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_apply_raises_on_non_windows(self) -> None:
        enforcer = WindowsEnforcer()
        config = _deny_policy("file_write")
        with pytest.raises(RuntimeError, match="not available"):
            enforcer.apply(config)

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="Windows required",
    )
    def test_apply_callable_on_windows(self) -> None:
        enforcer = WindowsEnforcer()
        assert callable(enforcer.apply)
