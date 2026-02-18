"""Tests for the macOS sandbox-exec profile generator."""

import sys

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.sandbox_exec import SandboxExecEnforcer


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


class TestSandboxExecEnforcer:
    """Tests for SandboxExecEnforcer profile generation."""

    def test_available_matches_platform(self) -> None:
        result = SandboxExecEnforcer.available()
        assert result == (sys.platform == "darwin")

    def test_generate_profile_has_version(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        profile = enforcer.generate_profile(config)

        assert "(version 1)" in profile

    def test_generate_profile_deny_file_write(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        profile = enforcer.generate_profile(config)

        assert "(deny file-write-data)" in profile
        assert "(deny file-write-create)" in profile
        assert "(deny file-write-unlink)" in profile

    def test_generate_profile_deny_network(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("web_fetch")
        profile = enforcer.generate_profile(config)

        assert "(deny network-outbound)" in profile

    def test_generate_profile_deny_shell_execute(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("shell_execute")
        profile = enforcer.generate_profile(config)

        assert "(deny process-exec)" in profile

    def test_write_profile_creates_file(self, tmp_path) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        output = tmp_path / "test.sb"

        result = enforcer.write_profile(config, output)

        assert result == output
        assert output.exists()
        content = output.read_text()
        assert "(version 1)" in content
        assert "(deny file-write-data)" in content

    def test_empty_policy_generates_minimal_profile(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _empty_policy()
        profile = enforcer.generate_profile(config)

        assert "(version 1)" in profile
        assert "(allow default)" in profile
        assert "(deny" not in profile
        assert "No deny rules found" in profile

    def test_generate_profile_has_allow_default(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        profile = enforcer.generate_profile(config)

        assert "(allow default)" in profile

    def test_generate_profile_includes_rule_name_comment(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="my-deny-rule", tools=["file_write"], action="deny"),
            ],
        )
        profile = enforcer.generate_profile(config)

        assert "my-deny-rule" in profile

    def test_generate_profile_wildcard_denies_all_ops(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("*")
        profile = enforcer.generate_profile(config)

        assert "(deny file-write-data)" in profile
        assert "(deny process-exec)" in profile
        assert "(deny network-outbound)" in profile

    def test_generate_profile_glob_pattern(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_*")
        profile = enforcer.generate_profile(config)

        assert "(deny file-write-data)" in profile
        assert "(deny file-write-unlink)" in profile

    def test_generate_profile_skips_allow_rules(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
        )
        profile = enforcer.generate_profile(config)

        assert "(deny file-write-data)" in profile
        # file_read has no SBPL mapping so it wouldn't appear regardless

    def test_generate_profile_unknown_tool_no_deny(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("unknown_tool")
        profile = enforcer.generate_profile(config)

        assert "(deny" not in profile

    def test_write_profile_creates_parent_dirs(self, tmp_path) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        output = tmp_path / "nested" / "dir" / "profile.sb"

        result = enforcer.write_profile(config, output)

        assert result == output
        assert output.exists()

    def test_generate_profile_no_duplicate_ops(self) -> None:
        """Denying both file_write and file_edit shouldn't duplicate file-write-data."""
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write", "file_edit")
        profile = enforcer.generate_profile(config)

        # file-write-data should appear only once
        assert profile.count("(deny file-write-data)") == 1
