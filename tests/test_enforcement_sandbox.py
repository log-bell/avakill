"""Tests for the macOS sandbox-exec profile generator."""

import sys

import pytest

from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    SandboxConfig,
    SandboxNetworkRules,
    SandboxPathRules,
)
from avakill.enforcement.sandbox_exec import SandboxExecEnforcer, SandboxProfileError


def _deny_policy(*tools: str, sandbox: SandboxConfig | None = None) -> PolicyConfig:
    """Create a policy that denies the given tools."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="deny-tools", tools=list(tools), action="deny"),
        ],
        sandbox=sandbox,
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
        config = _deny_policy(
            "file_write",
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=["/tmp"]),
            ),
        )
        profile = enforcer.generate_profile(config)

        # New behavior: scoped deny with require-not
        assert "(deny file-write*" in profile
        assert "require-not" in profile
        assert '(subpath "/tmp")' in profile

    def test_generate_profile_deny_network(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("web_fetch")
        profile = enforcer.generate_profile(config)

        # Network deny is always scoped (at minimum allows localhost)
        assert "(deny network-outbound" in profile
        assert '(remote tcp "localhost:*")' in profile

    def test_generate_profile_deny_shell_execute(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy(
            "shell_execute",
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(execute=["/usr/bin/python3"]),
            ),
        )
        profile = enforcer.generate_profile(config)

        # Scoped process-exec with literal shell paths, NOT bare global deny
        assert "(deny process-exec" in profile
        assert '(literal "/bin/sh")' in profile

    def test_write_profile_creates_file(self, tmp_path) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_write")
        output = tmp_path / "test.sb"

        result = enforcer.write_profile(config, output)

        assert result == output
        assert output.exists()
        content = output.read_text()
        assert "(version 1)" in content
        assert "(deny file-write*" in content

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
        config = _deny_policy(
            "*",
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(
                    write=["/tmp"],
                    execute=["/usr/bin/python3"],
                ),
            ),
        )
        profile = enforcer.generate_profile(config)

        assert "file-write" in profile
        assert "(deny process-exec" in profile
        assert "(deny network-outbound" in profile

    def test_generate_profile_glob_pattern(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("file_*")
        profile = enforcer.generate_profile(config)

        assert "file-write" in profile

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

        assert "file-write" in profile
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

        # file-write-data should appear only once (scoped)
        assert profile.count("(deny file-write-data") == 1

    def test_shell_execute_without_allowlist_raises(self) -> None:
        """Denying shell_execute without execute allowlist should raise."""
        enforcer = SandboxExecEnforcer()
        config = _deny_policy("shell_execute")

        with pytest.raises(SandboxProfileError, match="globally deny process-exec"):
            enforcer.generate_profile(config)

    def test_network_deny_with_allowlist(self) -> None:
        enforcer = SandboxExecEnforcer()
        config = _deny_policy(
            "web_fetch",
            sandbox=SandboxConfig(
                allow_network=SandboxNetworkRules(
                    connect=["api.anthropic.com:443"],
                ),
            ),
        )
        profile = enforcer.generate_profile(config)

        assert '(remote tcp "api.anthropic.com:443")' in profile
        assert '(remote tcp "localhost:*")' in profile
