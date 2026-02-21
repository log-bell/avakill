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
        result = runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()

    def test_sign_output_shows_path(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        assert result.exit_code == 0
        assert "signed" in result.output.lower() or "sig" in result.output.lower()

    def test_sign_from_env_var(self, runner: CliRunner, valid_policy: Path, key_hex: str) -> None:
        result = runner.invoke(
            cli,
            ["sign", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": key_hex},
        )
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()

    def test_sign_no_key_errors(self, runner: CliRunner, valid_policy: Path) -> None:
        result = runner.invoke(
            cli,
            ["sign", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": ""},
        )
        assert result.exit_code == 1
        assert "key" in result.output.lower()

    def test_sign_invalid_policy_errors(
        self, runner: CliRunner, tmp_path: Path, key_hex: str
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("{{not valid yaml")
        result = runner.invoke(cli, ["sign", str(bad), "--key", key_hex])
        assert result.exit_code == 1

    def test_sign_missing_file_errors(self, runner: CliRunner, key_hex: str) -> None:
        result = runner.invoke(cli, ["sign", "/nonexistent/policy.yaml", "--key", key_hex])
        assert result.exit_code == 1

    def test_generate_key(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["sign", "--generate-key"])
        assert result.exit_code == 0
        assert "AVAKILL_POLICY_KEY" in result.output
        # Should contain a 64-char hex string
        lines = result.output.strip().split("\n")
        key_line = [line for line in lines if "AVAKILL_POLICY_KEY" in line][0]
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
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", key_hex])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_verify_tampered_file(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        valid_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", key_hex])
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "mismatch" in result.output.lower()

    def test_verify_missing_sidecar(
        self, runner: CliRunner, valid_policy: Path, key_hex: str
    ) -> None:
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", key_hex])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "missing" in result.output.lower()

    def test_verify_missing_file(self, runner: CliRunner, key_hex: str) -> None:
        result = runner.invoke(cli, ["verify", "/nonexistent/policy.yaml", "--key", key_hex])
        assert result.exit_code == 1

    def test_verify_no_key_errors(self, runner: CliRunner, valid_policy: Path) -> None:
        result = runner.invoke(
            cli,
            ["verify", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": ""},
        )
        assert result.exit_code == 1

    def test_verify_from_env_var(self, runner: CliRunner, valid_policy: Path, key_hex: str) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        result = runner.invoke(
            cli,
            ["verify", str(valid_policy)],
            env={"AVAKILL_POLICY_KEY": key_hex},
        )
        assert result.exit_code == 0

    def test_verify_verbose(self, runner: CliRunner, valid_policy: Path, key_hex: str) -> None:
        runner.invoke(cli, ["sign", str(valid_policy), "--key", key_hex])
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", key_hex, "--verbose"])
        assert result.exit_code == 0
        assert "sha-256" in result.output.lower() or "sha256" in result.output.lower()


class TestApproveAutoSign:
    def test_approve_auto_signs_when_key_set(
        self, runner: CliRunner, tmp_path: Path, key_hex: str
    ) -> None:
        proposed = tmp_path / "avakill.proposed.yaml"
        proposed.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: test\n"
            "    tools: [file_read]\n"
            "    action: allow\n"
        )
        result = runner.invoke(
            cli,
            ["approve", str(proposed), "--yes"],
            env={"AVAKILL_POLICY_KEY": key_hex},
        )
        assert result.exit_code == 0
        target = tmp_path / "avakill.yaml"
        assert target.exists()
        sig = Path(str(target) + ".sig")
        assert sig.exists()

    def test_approve_auto_signs_ed25519_when_signing_key_set(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        nacl_signing = pytest.importorskip("nacl.signing")
        sk = nacl_signing.SigningKey.generate()
        private_hex = sk.encode().hex()

        proposed = tmp_path / "avakill.proposed.yaml"
        proposed.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: test\n"
            "    tools: [file_read]\n"
            "    action: allow\n"
        )
        result = runner.invoke(
            cli,
            ["approve", str(proposed), "--yes"],
            env={"AVAKILL_SIGNING_KEY": private_hex},
        )
        assert result.exit_code == 0
        target = tmp_path / "avakill.yaml"
        assert target.exists()
        sig = Path(str(target) + ".sig")
        assert sig.exists()
        assert sig.read_text().startswith("ed25519:")

    def test_approve_prefers_hmac_when_both_keys_set(
        self, runner: CliRunner, tmp_path: Path, key_hex: str
    ) -> None:
        nacl_signing = pytest.importorskip("nacl.signing")
        sk = nacl_signing.SigningKey.generate()
        private_hex = sk.encode().hex()

        proposed = tmp_path / "avakill.proposed.yaml"
        proposed.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: test\n"
            "    tools: [file_read]\n"
            "    action: allow\n"
        )
        result = runner.invoke(
            cli,
            ["approve", str(proposed), "--yes"],
            env={
                "AVAKILL_POLICY_KEY": key_hex,
                "AVAKILL_SIGNING_KEY": private_hex,
            },
        )
        assert result.exit_code == 0
        target = tmp_path / "avakill.yaml"
        assert target.exists()
        sig = Path(str(target) + ".sig")
        assert sig.exists()
        assert not sig.read_text().startswith("ed25519:")


# --- Ed25519 CLI tests (require PyNaCl) ---

nacl_signing = pytest.importorskip("nacl.signing")


@pytest.fixture
def ed25519_keys() -> tuple[str, str]:
    """Generate Ed25519 keypair, returning (private_hex, public_hex)."""
    sk = nacl_signing.SigningKey.generate()
    return sk.encode().hex(), sk.verify_key.encode().hex()


class TestSignEd25519Command:
    def test_sign_ed25519_creates_sidecar(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, _ = ed25519_keys
        result = runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()
        assert sig_path.read_text().startswith("ed25519:")

    def test_sign_ed25519_output_shows_type(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, _ = ed25519_keys
        result = runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        assert result.exit_code == 0
        assert "ed25519" in result.output.lower()

    def test_sign_ed25519_from_env_var(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, _ = ed25519_keys
        result = runner.invoke(
            cli,
            ["sign", "--ed25519", str(valid_policy)],
            env={"AVAKILL_SIGNING_KEY": private_hex},
        )
        assert result.exit_code == 0
        sig_path = Path(str(valid_policy) + ".sig")
        assert sig_path.exists()

    def test_sign_ed25519_no_key_errors(self, runner: CliRunner, valid_policy: Path) -> None:
        result = runner.invoke(
            cli,
            ["sign", "--ed25519", str(valid_policy)],
            env={"AVAKILL_SIGNING_KEY": ""},
        )
        assert result.exit_code == 1
        assert "key" in result.output.lower()


class TestVerifyEd25519Command:
    def test_verify_ed25519_valid_signature(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, public_hex = ed25519_keys
        runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", public_hex])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()
        assert "ed25519" in result.output.lower()

    def test_verify_ed25519_tampered_file(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, public_hex = ed25519_keys
        runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        valid_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        result = runner.invoke(cli, ["verify", str(valid_policy), "--key", public_hex])
        assert result.exit_code == 1
        assert "invalid" in result.output.lower()

    def test_verify_ed25519_from_env_var(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, public_hex = ed25519_keys
        runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        result = runner.invoke(
            cli,
            ["verify", str(valid_policy)],
            env={"AVAKILL_VERIFY_KEY": public_hex},
        )
        assert result.exit_code == 0

    def test_verify_ed25519_no_key_errors(
        self, runner: CliRunner, valid_policy: Path, ed25519_keys: tuple[str, str]
    ) -> None:
        private_hex, _ = ed25519_keys
        runner.invoke(cli, ["sign", "--ed25519", str(valid_policy), "--key", private_hex])
        result = runner.invoke(
            cli,
            ["verify", str(valid_policy)],
            env={"AVAKILL_VERIFY_KEY": "", "AVAKILL_POLICY_KEY": ""},
        )
        assert result.exit_code == 1
        assert "verify_key" in result.output.lower() or "key" in result.output.lower()


class TestKeygenCommand:
    def test_keygen_outputs_keys(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["keygen"])
        assert result.exit_code == 0
        assert "AVAKILL_SIGNING_KEY" in result.output
        assert "AVAKILL_VERIFY_KEY" in result.output

    def test_keygen_keys_are_valid_hex(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["keygen"])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        signing_line = [line for line in lines if "AVAKILL_SIGNING_KEY" in line][0]
        verify_line = [line for line in lines if "AVAKILL_VERIFY_KEY" in line][0]
        signing_hex = signing_line.split("=")[-1].strip()
        verify_hex = verify_line.split("=")[-1].strip()
        assert len(signing_hex) == 64  # 32 bytes
        assert len(verify_hex) == 64  # 32 bytes
        bytes.fromhex(signing_hex)
        bytes.fromhex(verify_hex)

    def test_keygen_keys_form_valid_keypair(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["keygen"])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        signing_line = [line for line in lines if "AVAKILL_SIGNING_KEY" in line][0]
        verify_line = [line for line in lines if "AVAKILL_VERIFY_KEY" in line][0]
        signing_hex = signing_line.split("=")[-1].strip()
        verify_hex = verify_line.split("=")[-1].strip()

        # Verify that the keys work together
        sk = nacl_signing.SigningKey(bytes.fromhex(signing_hex))
        vk = nacl_signing.VerifyKey(bytes.fromhex(verify_hex))
        signed = sk.sign(b"test message")
        vk.verify(signed)  # should not raise
