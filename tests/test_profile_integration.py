"""Integration tests for agent profiles with launcher and MCP proxy."""

from __future__ import annotations

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.profiles.loader import list_profiles, load_profile


class TestProfileIntegration:
    @pytest.mark.parametrize(
        "name",
        ["openclaw", "aider", "cline", "continue", "swe-agent"],
    )
    def test_profile_sandbox_is_valid(self, name):
        profile = load_profile(name)
        assert profile.sandbox is not None

    @pytest.mark.parametrize(
        "name",
        ["openclaw", "aider", "cline", "continue", "swe-agent"],
    )
    def test_profile_can_merge_with_policy(self, name):
        profile = load_profile(name)
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="test", tools=["*"], action="deny"),
            ],
            sandbox=profile.sandbox,
        )
        assert config.sandbox is not None

    def test_all_profiles_have_unique_names(self):
        names = list_profiles()
        assert len(names) == len(set(names))

    def test_mcp_native_agents_mention_mcp(self):
        for name in list_profiles():
            profile = load_profile(name)
            if profile.agent.mcp_native:
                assert "mcp" in profile.agent.description.lower(), (
                    f"{name} is MCP-native but description omits MCP"
                )
