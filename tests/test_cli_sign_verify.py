"""Tests for the avakill sign and verify CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def valid_policy(tmp_path: Path) -> Path:
    p = tmp_path / "avakill.yaml"
    p.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
    )
    return p


@pytest.fixture
def key_hex() -> str:
    return "aa" * 32


class TestSignCommand:
    def test_sign_creates_sidecar(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["sign", str(valid_policy), "--key", key_hex]
        )
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()

    def test_sign_output_shows_path(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["sign", str(valid_policy), "--key", key_hex]
        )
        assert result.exit_code == 0
        assert "signed" in result.output.lower() or "sig" in result.output.lower()

    def test_sign_from_env_var(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["sign", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": key_hex},
        )
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()

    def test_sign_no_key_errors(
        self, runner: CliRunner, valid_policy: Path
    ) -> None:
        result = runner.invoke(
            cli, ["sign", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": ""},
        )
        assert result.exit_code == 1
        assert "key" in result.output.lower()

    def test_sign_invalid_policy_errors(
        self, runner: CliRunner, tmp_path: Path, key_hex: str
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("{{not valid yaml")
        result = runner.invoke(
            cli, ["sign", str(bad), "--key", key_hex]
        )
        assert result.exit_code == 1

    def test_sign_missing_file_errors(
        self, runner: CliRunner, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["sign", "/nonexistent/policy.yaml", "--key", key_hex]
        )
        assert result.exit_code == 1

    def test_generate_key(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["sign", "--generate-key"])
        assert result.exit_code == 0
        assert "AVAKILL_POLICY_KEY" in result.output
        # Should contain a 64-char hex string
        lines = result.output.strip().split("\n")
        key_line = [l for l in lines if "AVAKILL_POLICY_KEY" in l][0]
        # Extract hex value
        hex_val = key_line.split("=")[-1].strip().strip('"').strip("'")
        assert len(hex_val) == 64
        bytes.fromhex(hex_val)  # should not raise


class TestVerifyCommand:
    def test_verify_valid_signature(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        # Sign first
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        result = runner.invoke(
            cli, ["verify", str(valid_policy), "--key", key_hex]
        )
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_verify_tampered_file(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        valid_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        result = runner.invoke(
            cli, ["verify", str(valid_policy), "--key", key_hex]
        )
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "mismatch" in result.output.lower()

    def test_verify_missing_sidecar(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["verify", str(valid_policy), "--key", key_hex]
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "missing" in result.output.lower()

    def test_verify_missing_file(
        self, runner: CliRunner, key_hex: str
    ) -> None:
        result = runner.invoke(
            cli, ["verify", "/nonexistent/policy.yaml", "--key", key_hex]
        )
        assert result.exit_code == 1

    def test_verify_no_key_errors(
        self, runner: CliRunner, valid_policy: Path
    ) -> None:
        result = runner.invoke(
            cli, ["verify", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": ""},
        )
        assert result.exit_code == 1

    def test_verify_from_env_var(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        result = runner.invoke(
            cli, ["verify", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": key_hex},
        )
        assert result.exit_code == 0

    def test_verify_verbose(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        result = runner.invoke(
            cli, ["verify", str(valid_policy), "--key", key_hex, "--verbose"]
        )
        assert result.exit_code == 0
        assert "sha-256" in result.output.lower() or "sha256" in result.output.lower()
