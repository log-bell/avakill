"""Tests for sandbox config generation in setup and rule_catalog."""

from __future__ import annotations

from pathlib import Path

import yaml

from avakill.cli.rule_catalog import build_policy_dict, generate_yaml
from avakill.launcher.backends.darwin_sbpl import (
    _resolve_binary_paths,
    _stable_parent,
    default_sandbox_config,
)


class TestDefaultSandboxConfig:
    def test_returns_sandbox_config(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        assert len(config.allow_paths.read) > 0
        assert str(tmp_path) in config.allow_paths.write
        assert "/tmp" in config.allow_paths.write
        assert len(config.allow_network.connect) > 0

    def test_includes_system_paths(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        read_paths = config.allow_paths.read
        assert "/usr" in read_paths
        assert "/bin" in read_paths

    def test_includes_api_endpoints(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        connects = config.allow_network.connect
        assert "api.anthropic.com:443" in connects
        assert "api.openai.com:443" in connects

    def test_workspace_defaults_to_cwd(self) -> None:
        config = default_sandbox_config()
        cwd = str(Path.cwd().resolve())
        assert cwd in config.allow_paths.write

    def test_serializes_to_dict(self, tmp_path: Path) -> None:
        config = default_sandbox_config(workspace=tmp_path)
        d = config.model_dump()
        assert "allow_paths" in d
        assert "allow_network" in d
        assert isinstance(d["allow_paths"]["read"], list)


class TestStableParent:
    def test_fnm_multishells_truncated(self) -> None:
        path = "/Users/me/.local/state/fnm_multishells/65523_123456/bin"
        assert _stable_parent(path) == "/Users/me/.local/state/fnm_multishells"

    def test_fnm_node_versions_truncated(self) -> None:
        path = "/Users/me/.local/share/fnm/node-versions/v22.17.1/installation/bin"
        assert _stable_parent(path) == "/Users/me/.local/share/fnm/node-versions"

    def test_nvm_versions_truncated(self) -> None:
        path = "/Users/me/.nvm/versions/node/v20.0.0/bin"
        assert _stable_parent(path) == "/Users/me/.nvm/versions"

    def test_volta_truncated(self) -> None:
        path = "/Users/me/.volta/bin"
        assert _stable_parent(path) == "/Users/me/.volta"

    def test_normal_path_unchanged(self) -> None:
        path = "/opt/homebrew/bin"
        assert _stable_parent(path) == "/opt/homebrew/bin"

    def test_usr_bin_unchanged(self) -> None:
        path = "/usr/bin"
        assert _stable_parent(path) == "/usr/bin"


class TestResolveBinaryPaths:
    def test_nonexistent_binary_returns_empty(self) -> None:
        exec_dirs, read_dirs = _resolve_binary_paths("nonexistent_binary_xyz_123")
        assert exec_dirs == []
        assert read_dirs == []

    def test_resolves_real_binary(self) -> None:
        """A real binary like 'git' should return at least one exec dir."""
        exec_dirs, read_dirs = _resolve_binary_paths("git")
        assert len(exec_dirs) >= 1

    def test_symlink_followed(self, tmp_path: Path) -> None:
        """When a binary is a symlink, both shim and real dirs are returned."""
        # Create a fake binary and symlink
        real_dir = tmp_path / "real" / "bin"
        real_dir.mkdir(parents=True)
        real_bin = real_dir / "mybinary"
        real_bin.write_text("#!/bin/sh\n")
        real_bin.chmod(0o755)

        shim_dir = tmp_path / "shim" / "bin"
        shim_dir.mkdir(parents=True)
        shim_bin = shim_dir / "mybinary"
        shim_bin.symlink_to(real_bin)

        import os

        orig_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{shim_dir}:{orig_path}"
        try:
            exec_dirs, read_dirs = _resolve_binary_paths("mybinary")
            assert str(shim_dir) in exec_dirs
            assert str(real_dir) in exec_dirs
            assert str(real_dir) in read_dirs
        finally:
            os.environ["PATH"] = orig_path


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
