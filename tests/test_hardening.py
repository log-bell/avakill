"""Tests for Phase 3: OS-Level Hardening."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from avakill.cli.main import cli

# ---------------------------------------------------------------------------
# Component 5: Capability Detection Utility
# ---------------------------------------------------------------------------


class TestCheckImmutable:
    """Test check_immutable utility function."""

    def test_returns_false_for_normal_file(self, tmp_path: Path) -> None:
        from avakill.hardening import check_immutable

        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert check_immutable(f) is False

    def test_returns_false_for_nonexistent_file(self, tmp_path: Path) -> None:
        from avakill.hardening import check_immutable

        assert check_immutable(tmp_path / "nonexistent.txt") is False


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="os.getuid()/os.getgid() not available on Windows",
)
class TestCheckFilePermissions:
    """Test check_file_permissions utility function."""

    def test_returns_correct_metadata(self, tmp_path: Path) -> None:
        from avakill.hardening import check_file_permissions

        f = tmp_path / "test.txt"
        f.write_text("hello")
        os.chmod(f, 0o644)

        result = check_file_permissions(f)
        assert result["mode"] == "0o644"
        assert result["uid"] == os.getuid()
        assert result["gid"] == os.getgid()
        assert result["writable_by_others"] is False

    def test_detects_world_writable(self, tmp_path: Path) -> None:
        from avakill.hardening import check_file_permissions

        f = tmp_path / "test.txt"
        f.write_text("hello")
        os.chmod(f, 0o666)

        result = check_file_permissions(f)
        assert result["writable_by_others"] is True


# ---------------------------------------------------------------------------
# Component 1: avakill harden CLI command
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="chattr/schg immutable flags not available on Windows"
)
class TestHardenCommand:
    """Test avakill harden CLI command."""

    def test_help_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["harden", "--help"])
        assert result.exit_code == 0
        assert "--chattr" in result.output
        assert "--schg" in result.output
        assert "--selinux" in result.output
        assert "--apparmor" in result.output
        assert "--seccomp" in result.output
        assert "--output" in result.output

    def test_missing_policy_file_chattr(self, tmp_path: Path) -> None:
        runner = CliRunner()
        missing = tmp_path / "nonexistent.yaml"
        with patch("os.geteuid", return_value=0):
            result = runner.invoke(cli, ["harden", "--chattr", str(missing)])
        assert result.exit_code != 0

    def test_chattr_without_root(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["harden", "--chattr", str(policy)])
        assert result.exit_code != 0
        assert "root" in result.output.lower() or "privileges" in result.output.lower()

    def test_schg_without_root(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["harden", "--schg", str(policy)])
        assert result.exit_code != 0

    def test_chattr_mock_success(self, tmp_path: Path) -> None:
        """Mock test: chattr calls set_immutable_linux on Linux with root."""
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        with (
            patch("sys.platform", "linux"),
            patch("os.geteuid", return_value=0),
            patch("avakill.hardening.set_immutable_linux") as mock_set,
        ):
            result = runner.invoke(cli, ["harden", "--chattr", str(policy)])
        assert result.exit_code == 0
        mock_set.assert_called_once()

    def test_schg_mock_success(self, tmp_path: Path) -> None:
        """Mock test: schg calls set_immutable_macos on macOS with root."""
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        with (
            patch("sys.platform", "darwin"),
            patch("os.geteuid", return_value=0),
            patch("avakill.hardening.set_immutable_macos") as mock_set,
        ):
            result = runner.invoke(cli, ["harden", "--schg", str(policy)])
        assert result.exit_code == 0
        mock_set.assert_called_once()

    def test_unsupported_platform(self, tmp_path: Path) -> None:
        """No flags on unsupported platform should error gracefully."""
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        with patch("sys.platform", "win32"):
            result = runner.invoke(cli, ["harden", str(policy)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Component 2: avakill check-hardening CLI command
# ---------------------------------------------------------------------------


class TestCheckHardeningCommand:
    """Test avakill check-hardening CLI command."""

    def test_help_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["check-hardening", "--help"])
        assert result.exit_code == 0

    def test_regular_file_no_immutable(self, tmp_path: Path) -> None:
        """Regular file should show immutable flag as not set."""
        runner = CliRunner()
        policy = tmp_path / "avakill.yaml"
        policy.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
        result = runner.invoke(cli, ["check-hardening", str(policy)])
        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "immutable" in output_lower

    def test_missing_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        missing = tmp_path / "nonexistent.yaml"
        result = runner.invoke(cli, ["check-hardening", str(missing)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Component 3: Hardening Templates
# ---------------------------------------------------------------------------


class TestTemplateOutput:
    """Test hardening template content."""

    def test_selinux_template_content(self) -> None:
        from avakill.hardening import get_template_content

        content = get_template_content("selinux.te")
        assert "avakill_policy_t" in content
        assert "avakill_t" in content
        assert "neverallow" in content

    def test_apparmor_template_content(self) -> None:
        from avakill.hardening import get_template_content

        content = get_template_content("apparmor.profile")
        assert "deny" in content

    def test_seccomp_template_valid_json(self) -> None:
        from avakill.hardening import get_template_content

        content = get_template_content("seccomp.json")
        data = json.loads(content)
        assert "defaultAction" in data
        assert "syscalls" in data

    def test_seccomp_blocks_expected_syscalls(self) -> None:
        from avakill.hardening import get_template_content

        content = get_template_content("seccomp.json")
        data = json.loads(content)
        all_names: list[str] = []
        for entry in data.get("syscalls", []):
            all_names.extend(entry.get("names", []))
        for syscall in (
            "unlink",
            "unlinkat",
            "rename",
            "renameat",
            "renameat2",
            "chmod",
            "fchmod",
            "fchmodat",
            "ptrace",
            "process_vm_writev",
        ):
            assert syscall in all_names, f"Expected {syscall} in blocked syscalls"

    def test_harden_selinux_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["harden", "--selinux"])
        assert result.exit_code == 0
        assert "avakill_policy_t" in result.output

    def test_harden_apparmor_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["harden", "--apparmor"])
        assert result.exit_code == 0
        assert "deny" in result.output

    def test_harden_seccomp_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["harden", "--seccomp"])
        assert result.exit_code == 0
        assert "defaultAction" in result.output

    def test_harden_template_to_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        out = tmp_path / "seccomp.json"
        result = runner.invoke(cli, ["harden", "--seccomp", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "defaultAction" in data


# ---------------------------------------------------------------------------
# Component 4: Docker / Kubernetes Examples
# ---------------------------------------------------------------------------


class TestDockerComposeTemplate:
    """Test Docker compose template is valid YAML."""

    @pytest.fixture()
    def compose_path(self) -> Path:
        return Path(__file__).parent.parent / "examples" / "docker-compose.hardened.yml"

    def test_is_valid_yaml(self, compose_path: Path) -> None:
        data = yaml.safe_load(compose_path.read_text())
        assert isinstance(data, dict)
        assert "services" in data

    def test_contains_security_directives(self, compose_path: Path) -> None:
        content = compose_path.read_text()
        assert "read_only" in content
        assert "cap_drop" in content
        assert "no-new-privileges" in content


class TestSystemdUnit:
    """Test systemd unit contains expected directives."""

    @pytest.fixture()
    def unit_path(self) -> Path:
        return Path(__file__).parent.parent / "examples" / "systemd" / "avakill.service"

    def test_contains_hardening_directives(self, unit_path: Path) -> None:
        content = unit_path.read_text()
        assert "CapabilityBoundingSet" in content
        assert "ProtectSystem" in content
        assert "NoNewPrivileges" in content
        assert "ReadOnlyPaths" in content
