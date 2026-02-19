"""Tests for allow-based SBPL profile generation."""

from __future__ import annotations

from pathlib import Path

from avakill.core.models import SandboxConfig, SandboxNetworkRules, SandboxPathRules
from avakill.launcher.backends.darwin_sbpl import generate_sbpl_profile


class TestSBPLProfileGeneration:
    def test_empty_config_produces_deny_default(self):
        config = SandboxConfig()
        profile = generate_sbpl_profile(config)
        assert "(version 1)" in profile
        assert "(deny default)" in profile

    def test_read_paths_produce_allow_file_read(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["/usr", "/lib"]),
        )
        profile = generate_sbpl_profile(config)
        assert '(allow file-read* (subpath "/usr"))' in profile
        assert '(allow file-read* (subpath "/lib"))' in profile

    def test_write_paths_produce_allow_file_write(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(write=["/tmp", "/Users/me/project"]),
        )
        profile = generate_sbpl_profile(config)
        # /tmp may resolve to /private/tmp on macOS
        resolved_tmp = str(Path("/tmp").resolve())
        assert f'(allow file-write* (subpath "{resolved_tmp}"))' in profile
        assert '(allow file-write* (subpath "/Users/me/project"))' in profile

    def test_execute_paths_produce_allow_process_exec(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(execute=["/usr/bin/node"]),
        )
        profile = generate_sbpl_profile(config)
        assert '(allow process-exec (literal "/usr/bin/node"))' in profile

    def test_network_connect_produces_allow_network_outbound(self):
        config = SandboxConfig(
            allow_network=SandboxNetworkRules(
                connect=["api.anthropic.com:443", "api.openai.com:443"],
            ),
        )
        profile = generate_sbpl_profile(config)
        assert "(allow network-outbound" in profile
        assert "api.anthropic.com" in profile

    def test_always_allows_sysctl_and_mach(self):
        """Baseline operations always allowed for process to function."""
        config = SandboxConfig()
        profile = generate_sbpl_profile(config)
        assert "(allow sysctl-read)" in profile
        assert "(allow mach-lookup)" in profile

    def test_tilde_expanded_in_paths(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["~/project"]),
        )
        profile = generate_sbpl_profile(config)
        assert "~" not in profile
        assert "/Users/" in profile or "/home/" in profile

    def test_combined_read_write_execute(self):
        config = SandboxConfig(
            allow_paths=SandboxPathRules(
                read=["/usr"],
                write=["/tmp"],
                execute=["/usr/bin/python3"],
            ),
        )
        profile = generate_sbpl_profile(config)
        assert "(deny default)" in profile
        assert "file-read*" in profile
        assert "file-write*" in profile
        assert "process-exec" in profile
