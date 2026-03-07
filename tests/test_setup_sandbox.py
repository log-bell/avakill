"""Tests for sandbox config generation in setup and rule_catalog."""

from __future__ import annotations

from pathlib import Path

import yaml

from avakill.cli.rule_catalog import build_policy_dict, generate_yaml
from avakill.launcher.backends.darwin_sbpl import default_sandbox_config


class TestDefaultSandboxConfig:
    def test_workspace_in_write_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert str(tmp_path) in config.allow_paths.write

    def test_tmp_in_write_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert "/tmp" in config.allow_paths.write

    def test_has_default_deny_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        deny = config.deny_paths.read
        assert "~/.ssh" in deny
        assert "~/.aws" in deny
        assert "~/.gnupg" in deny
        assert "~/Library/Keychains" in deny

    def test_has_network_defaults(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert "api.anthropic.com:443" in config.allow_network.connect

    def test_workspace_defaults_to_cwd(self) -> None:
        config = default_sandbox_config()
        cwd = str(Path.cwd().resolve())
        assert cwd in config.allow_paths.write

    def test_no_read_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert config.allow_paths.read == []

    def test_no_execute_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert config.allow_paths.execute == []

    def test_serializes_to_dict(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        d = config.model_dump()
        assert "allow_paths" in d
        assert "deny_paths" in d
        assert "allow_network" in d


class TestBuildPolicyDictWithSandbox:
    def test_sandbox_config_included(self) -> None:
        sandbox = {"allow_paths": {"read": ["/usr"], "write": ["/tmp"]}}
        result = build_policy_dict([], sandbox_config=sandbox)
        assert "sandbox" in result
        assert result["sandbox"]["allow_paths"]["read"] == ["/usr"]

    def test_no_sandbox_when_none(self) -> None:
        result = build_policy_dict([])
        assert "sandbox" not in result

    def test_generate_yaml_with_sandbox(self) -> None:
        sandbox = {"allow_paths": {"read": ["/usr"], "write": ["/tmp"]}}
        yaml_str = generate_yaml([], sandbox_config=sandbox)
        data = yaml.safe_load(yaml_str)
        assert "sandbox" in data
        assert data["sandbox"]["allow_paths"]["read"] == ["/usr"]

    def test_generate_yaml_without_sandbox(self) -> None:
        yaml_str = generate_yaml([])
        data = yaml.safe_load(yaml_str)
        assert "sandbox" not in data
