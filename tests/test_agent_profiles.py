"""Tests for AgentProfile model and profile loader."""

from __future__ import annotations

import pytest

from avakill.core.models import SandboxConfig, SandboxPathRules
from avakill.profiles.loader import (
    get_builtin_profile_dir,
    list_profiles,
    load_profile,
)
from avakill.profiles.models import AgentMetadata, AgentProfile


class TestAgentProfileModel:
    def test_minimal_profile(self):
        profile = AgentProfile(
            agent=AgentMetadata(name="test-agent"),
        )
        assert profile.agent.name == "test-agent"
        assert profile.sandbox is not None

    def test_profile_with_sandbox(self):
        profile = AgentProfile(
            agent=AgentMetadata(
                name="openclaw",
                command=["openclaw", "start"],
                mcp_native=True,
            ),
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(read=["/usr"]),
            ),
        )
        assert profile.agent.command == ["openclaw", "start"]
        assert profile.agent.mcp_native is True
        assert "/usr" in profile.sandbox.allow_paths.read

    def test_profile_protection_modes(self):
        profile = AgentProfile(
            agent=AgentMetadata(
                name="test",
                supports_hooks=True,
                mcp_native=True,
            ),
        )
        assert profile.agent.supports_hooks is True
        assert profile.agent.mcp_native is True

    def test_profile_detection_hints(self):
        profile = AgentProfile(
            agent=AgentMetadata(
                name="openclaw",
                detect_paths=["~/.openclaw", "~/.openclaw/config.json"],
                detect_commands=["openclaw"],
            ),
        )
        assert "~/.openclaw" in profile.agent.detect_paths
        assert "openclaw" in profile.agent.detect_commands


class TestProfileLoader:
    def test_list_profiles_returns_builtin(self):
        profiles = list_profiles()
        assert isinstance(profiles, list)

    def test_get_builtin_profile_dir_exists(self):
        d = get_builtin_profile_dir()
        assert d.is_dir()

    def test_load_profile_from_yaml(self, tmp_path):
        profile_yaml = tmp_path / "test.yaml"
        profile_yaml.write_text(
            "agent:\n"
            "  name: test-agent\n"
            "  command: ['echo', 'hello']\n"
            "sandbox:\n"
            "  allow_paths:\n"
            "    read: ['/usr']\n"
        )
        profile = load_profile(profile_yaml)
        assert profile.agent.name == "test-agent"
        assert profile.agent.command == ["echo", "hello"]
        assert "/usr" in profile.sandbox.allow_paths.read

    def test_load_profile_by_name_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_profile("nonexistent-agent-xyz")

    def test_load_profile_merges_with_policy(self, tmp_path):
        profile_yaml = tmp_path / "base.yaml"
        profile_yaml.write_text(
            "agent:\n"
            "  name: test\n"
            "sandbox:\n"
            "  allow_paths:\n"
            "    read: ['/usr']\n"
            "    write: ['/tmp']\n"
        )
        profile = load_profile(profile_yaml)
        assert "/usr" in profile.sandbox.allow_paths.read
        assert "/tmp" in profile.sandbox.allow_paths.write
