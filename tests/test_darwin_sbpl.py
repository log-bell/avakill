"""Tests for deny-default SBPL profile generation."""

from __future__ import annotations

import sys

import pytest

from avakill.core.models import (
    SandboxConfig,
    SandboxDenyPaths,
    SandboxNetworkRules,
    SandboxPathRules,
)
from avakill.launcher.backends.darwin_sbpl import generate_sbpl_profile


@pytest.mark.skipif(sys.platform != "darwin", reason="SBPL profiles are macOS-only")
class TestSBPLProfileGeneration:
    def test_empty_config_produces_deny_default(self):
        config = SandboxConfig()
        profile = generate_sbpl_profile(config)
        assert "(version 1)" in profile
        assert "(deny default)" in profile

    def test_profile_always_has_broad_reads(self):
        config = SandboxConfig()
        profile = generate_sbpl_profile(config)
        assert '(subpath "/usr/lib")' in profile
        assert '(subpath "/System")' in profile
        assert '(subpath (param "HOME"))' in profile

    def test_write_paths_produce_parameterized_writes(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(write=["/tmp", "/Users/me/project"]),
        )
        profile = generate_sbpl_profile(config)
        assert '(param "WRITE_PATH_0")' in profile
        assert '(param "WRITE_PATH_1")' in profile

    def test_deny_paths_produce_parameterized_denials(self):
        config = SandboxConfig(
            deny_paths=SandboxDenyPaths(read=["~/.ssh", "~/.aws"]),
        )
        profile = generate_sbpl_profile(config)
        assert '(deny file-read* (subpath (param "DENY_PATH_0")))' in profile
        assert '(deny file-read* (subpath (param "DENY_PATH_1")))' in profile

    def test_network_connect_produces_allow_network_outbound(self):
        config = SandboxConfig(
            allow_network=SandboxNetworkRules(
                connect=["api.anthropic.com:443", "api.openai.com:443"],
            ),
        )
        profile = generate_sbpl_profile(config)
        assert "(allow network-outbound" in profile
        assert '"*:443"' in profile

    def test_always_allows_sysctl_and_enumerated_mach(self):
        """Baseline operations always allowed for process to function."""
        config = SandboxConfig()
        profile = generate_sbpl_profile(config)
        assert "(allow sysctl-read)" in profile
        assert "(allow mach-lookup" in profile
        assert "com.apple.trustd" in profile

    def test_combined_write_deny_network(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(write=["/tmp"]),
            deny_paths=SandboxDenyPaths(read=["~/.ssh"]),
            allow_network=SandboxNetworkRules(connect=["api.openai.com:443"]),
        )
        profile = generate_sbpl_profile(config)
        assert "(deny default)" in profile
        assert "file-write*" in profile
        assert "deny file-read*" in profile
        assert "network-outbound" in profile
