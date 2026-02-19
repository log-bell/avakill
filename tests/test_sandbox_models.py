"""Tests for sandbox policy models."""

from __future__ import annotations

import yaml

from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    SandboxConfig,
    SandboxNetworkRules,
    SandboxPathRules,
    SandboxResourceLimits,
)


class TestSandboxConfig:
    """Tests for SandboxConfig and related models."""

    def test_default_sandbox_config(self) -> None:
        config = SandboxConfig()
        assert config.allow_paths.read == []
        assert config.allow_paths.write == []
        assert config.allow_paths.execute == []
        assert config.allow_network.connect == []
        assert config.allow_network.bind == []
        assert config.resource_limits.max_memory_mb is None
        assert config.resource_limits.max_open_files is None
        assert config.resource_limits.max_processes is None
        assert config.resource_limits.timeout_seconds is None
        assert config.inherit_env is True
        assert config.inject_hooks is True

    def test_sandbox_with_paths(self) -> None:
        config = SandboxConfig(
            allow_paths=SandboxPathRules(
                read=["/usr", "/bin", "/lib"],
                write=["/tmp", "~/project"],
                execute=["/usr/bin/node", "/usr/bin/python3"],
            )
        )
        assert "/usr" in config.allow_paths.read
        assert "/tmp" in config.allow_paths.write
        assert "/usr/bin/node" in config.allow_paths.execute

    def test_sandbox_with_network_rules(self) -> None:
        config = SandboxConfig(
            allow_network=SandboxNetworkRules(
                connect=["api.anthropic.com:443", "api.openai.com:443"],
                bind=["localhost:8080"],
            )
        )
        assert len(config.allow_network.connect) == 2
        assert "api.anthropic.com:443" in config.allow_network.connect
        assert "localhost:8080" in config.allow_network.bind

    def test_sandbox_with_resource_limits(self) -> None:
        config = SandboxConfig(
            resource_limits=SandboxResourceLimits(
                max_memory_mb=512,
                max_open_files=1024,
                max_processes=50,
                timeout_seconds=3600,
            )
        )
        assert config.resource_limits.max_memory_mb == 512
        assert config.resource_limits.max_open_files == 1024
        assert config.resource_limits.max_processes == 50
        assert config.resource_limits.timeout_seconds == 3600

    def test_sandbox_in_policy_config(self) -> None:
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[PolicyRule(name="allow-all", tools=["*"], action="allow")],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(read=["/usr"]),
            ),
        )
        assert config.sandbox is not None
        assert "/usr" in config.sandbox.allow_paths.read

    def test_policy_config_without_sandbox_backward_compatible(self) -> None:
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[PolicyRule(name="allow-all", tools=["*"], action="allow")],
        )
        assert config.sandbox is None

    def test_sandbox_from_yaml_round_trip(self) -> None:
        yaml_str = """\
version: "1.0"
default_action: deny
policies:
  - name: allow-reads
    tools: ["*_read"]
    action: allow
sandbox:
  allow_paths:
    read: ["/usr", "/bin"]
    write: ["/tmp"]
    execute: ["/usr/bin/python3"]
  allow_network:
    connect: ["api.anthropic.com:443"]
  resource_limits:
    max_memory_mb: 256
    timeout_seconds: 600
  inherit_env: true
  inject_hooks: false
"""
        data = yaml.safe_load(yaml_str)
        config = PolicyConfig(**data)

        assert config.sandbox is not None
        assert config.sandbox.allow_paths.read == ["/usr", "/bin"]
        assert config.sandbox.allow_paths.write == ["/tmp"]
        assert config.sandbox.allow_network.connect == ["api.anthropic.com:443"]
        assert config.sandbox.resource_limits.max_memory_mb == 256
        assert config.sandbox.resource_limits.timeout_seconds == 600
        assert config.sandbox.inherit_env is True
        assert config.sandbox.inject_hooks is False
