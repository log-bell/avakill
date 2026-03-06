"""Tests for avakill sandbox verify command."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from avakill.cli.main import cli


def _write_policy(tmp_path: Path, sandbox: dict | None = None) -> Path:
    data: dict = {
        "version": "1.0",
        "default_action": "allow",
        "policies": [{"name": "allow-all", "tools": ["*"], "action": "allow"}],
    }
    if sandbox is not None:
        data["sandbox"] = sandbox
    path = tmp_path / "test-policy.yaml"
    path.write_text(yaml.dump(data))
    return path


class TestSandboxVerify:
    def test_verify_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["sandbox", "verify", "--help"])
        assert result.exit_code == 0
        assert "Verify" in result.output

    def test_verify_missing_policy(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["sandbox", "verify", "--policy", "/nonexistent/policy.yaml"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_verify_no_sandbox_section(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["sandbox", "verify", "--policy", str(policy_path)])
        assert result.exit_code == 1
        assert "sandbox" in result.output.lower()

    def test_verify_non_darwin_platform(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.setattr("sys.platform", "linux")  # type: ignore[attr-defined]
        policy_path = _write_policy(
            tmp_path,
            sandbox={"allow_paths": {"read": ["/usr"], "write": ["/tmp"]}},
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["sandbox", "verify", "--policy", str(policy_path)])
        assert result.exit_code == 1
        assert "macOS" in result.output or "macos" in result.output.lower()
