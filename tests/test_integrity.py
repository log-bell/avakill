"""Tests for the AvaKill PolicyIntegrity module."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from avakill.core.integrity import FileSnapshot, PolicyIntegrity
from avakill.core.models import PolicyConfig


class TestFileSnapshot:
    def test_create_from_path(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("version: '1.0'\n")
        snap = FileSnapshot.from_path(str(p))
        assert snap.path == os.path.realpath(str(p))
        assert snap.size > 0
        assert snap.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()

    def test_stat_precheck_unchanged(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("hello")
        snap = FileSnapshot.from_path(str(p))
        ok, msg = snap.verify(str(p))
        assert ok is True
        assert "stat pre-check" in msg

    def test_detects_content_change(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("original content here")
        snap = FileSnapshot.from_path(str(p))
        p.write_text("tampered!")
        ok, msg = snap.verify(str(p))
        assert ok is False

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod is a no-op on Windows")
    def test_detects_permission_change(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("test")
        snap = FileSnapshot.from_path(str(p))
        os.chmod(str(p), 0o777)
        ok, msg = snap.verify(str(p))
        assert ok is False
        assert "permissions" in msg.lower() or "mode" in msg.lower()

    def test_detects_file_replacement(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("original content for replacement test")
        snap = FileSnapshot.from_path(str(p))
        # Replace: delete and recreate (new inode, different content)
        p.unlink()
        p.write_text("replaced content")
        ok, msg = snap.verify(str(p))
        assert ok is False

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Symlink creation requires elevated privileges on Windows"
    )
    def test_detects_symlink_redirect(self, tmp_path: Path) -> None:
        real = tmp_path / "real.yaml"
        real.write_text("real content")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)
        # Baseline on real path
        snap = FileSnapshot.from_path(str(real))
        # Verify via symlink -> different realpath
        ok, msg = snap.verify(str(link))
        assert ok is True  # realpath resolves to same file

        # Now redirect symlink to a different file
        evil = tmp_path / "evil.yaml"
        evil.write_text("evil content")
        link.unlink()
        link.symlink_to(evil)
        ok, msg = snap.verify(str(link))
        assert ok is False
        assert "path" in msg.lower() or "redirect" in msg.lower()


class TestHMACSigning:
    @pytest.fixture
    def key(self) -> bytes:
        return bytes.fromhex("aa" * 32)

    @pytest.fixture
    def policy_file(self, tmp_path: Path) -> Path:
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

    def test_sign_creates_sidecar(self, policy_file: Path, key: bytes) -> None:
        sig_path = PolicyIntegrity.sign_file(policy_file, key)
        assert sig_path.exists()
        assert sig_path == policy_file.with_suffix(".yaml.sig")
        assert len(sig_path.read_text().strip()) == 64  # hex sha256

    def test_verify_valid_signature(self, policy_file: Path, key: bytes) -> None:
        PolicyIntegrity.sign_file(policy_file, key)
        assert PolicyIntegrity.verify_file(policy_file, key) is True

    def test_verify_tampered_content(self, policy_file: Path, key: bytes) -> None:
        PolicyIntegrity.sign_file(policy_file, key)
        policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        assert PolicyIntegrity.verify_file(policy_file, key) is False

    def test_verify_bad_signature(self, policy_file: Path, key: bytes) -> None:
        PolicyIntegrity.sign_file(policy_file, key)
        sig_path = policy_file.with_suffix(".yaml.sig")
        sig_path.write_text("0" * 64)
        assert PolicyIntegrity.verify_file(policy_file, key) is False

    def test_verify_missing_sidecar(self, policy_file: Path, key: bytes) -> None:
        assert PolicyIntegrity.verify_file(policy_file, key) is False

    def test_verify_wrong_key(self, policy_file: Path, key: bytes) -> None:
        PolicyIntegrity.sign_file(policy_file, key)
        wrong_key = bytes.fromhex("bb" * 32)
        assert PolicyIntegrity.verify_file(policy_file, wrong_key) is False

    def test_sign_roundtrip_different_keys_fail(self, policy_file: Path) -> None:
        key_a = bytes.fromhex("aa" * 32)
        key_b = bytes.fromhex("bb" * 32)
        PolicyIntegrity.sign_file(policy_file, key_a)
        assert PolicyIntegrity.verify_file(policy_file, key_b) is False


@pytest.fixture
def signing_key() -> bytes:
    return bytes.fromhex("cc" * 32)


@pytest.fixture
def signed_policy(tmp_path: Path, signing_key: bytes) -> Path:
    """Create a signed policy file."""
    p = tmp_path / "avakill.yaml"
    p.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
    )
    PolicyIntegrity.sign_file(p, signing_key)
    return p


class TestTOCTOUSafeLoading:
    def test_loads_valid_signed_policy(self, signed_policy: Path, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(signed_policy)
        assert isinstance(config, PolicyConfig)
        assert config.version == "1.0"
        assert len(config.policies) == 1

    def test_rejects_unsigned_when_key_set(self, tmp_path: Path, signing_key: bytes) -> None:
        p = tmp_path / "unsigned.yaml"
        p.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        pi = PolicyIntegrity(signing_key=signing_key)
        # Should fall back to deny-all (no last-known-good)
        config = pi.load_verified(p)
        assert config.default_action == "deny"
        assert len(config.policies) == 0

    def test_accepts_unsigned_when_no_key(self, tmp_path: Path) -> None:
        p = tmp_path / "unsigned.yaml"
        p.write_text(
            "version: '1.0'\ndefault_action: allow\n"
            "policies:\n"
            "  - name: test\n"
            "    tools: ['*']\n"
            "    action: allow\n"
        )
        pi = PolicyIntegrity(signing_key=None)
        config = pi.load_verified(p)
        assert config.default_action == "allow"

    def test_rejects_tampered_signed_policy(self, signed_policy: Path, signing_key: bytes) -> None:
        # Tamper with content after signing
        signed_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(signed_policy)
        # Falls back to deny-all
        assert config.default_action == "deny"


class TestFailClosed:
    def test_missing_file_returns_deny_all(self, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified("/nonexistent/policy.yaml")
        assert config.default_action == "deny"
        assert len(config.policies) == 0

    def test_bad_hmac_falls_back_to_last_known_good(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        # First: load valid policy (becomes last-known-good)
        good = pi.load_verified(signed_policy)
        assert good.version == "1.0"
        assert len(good.policies) == 1

        # Tamper with the file
        signed_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        # Should fall back to last-known-good
        fallback = pi.load_verified(signed_policy)
        assert len(fallback.policies) == 1  # still the good policy

    def test_invalid_yaml_falls_back(self, tmp_path: Path, signing_key: bytes) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("{{not: valid: yaml::")
        # Sign the bad content (signature is valid but content isn't YAML)
        PolicyIntegrity.sign_file(p, signing_key)
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(p)
        assert config.default_action == "deny"  # deny-all fallback

    def test_invalid_schema_falls_back(self, tmp_path: Path, signing_key: bytes) -> None:
        p = tmp_path / "bad_schema.yaml"
        p.write_text("version: '2.0'\ndefault_action: deny\npolicies: []\n")
        PolicyIntegrity.sign_file(p, signing_key)
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(p)
        assert config.default_action == "deny"  # deny-all fallback

    def test_no_fallback_uses_deny_all(self, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        assert pi.get_last_known_good() is None
        config = pi.load_verified("/nonexistent.yaml")
        assert config.default_action == "deny"
        assert len(config.policies) == 0

    def test_get_last_known_good_after_load(self, signed_policy: Path, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        pi.load_verified(signed_policy)
        lkg = pi.get_last_known_good()
        assert lkg is not None
        assert lkg.version == "1.0"


class TestPolicyIntegrityBaseline:
    def test_set_baseline(self, signed_policy: Path, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        snap = pi.set_baseline(signed_policy)
        assert isinstance(snap, FileSnapshot)
        assert snap.size > 0

    def test_check_integrity_unchanged(self, signed_policy: Path, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        pi.set_baseline(signed_policy)
        ok, msg = pi.check_integrity(signed_policy)
        assert ok is True

    def test_check_integrity_tampered(self, signed_policy: Path, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        pi.set_baseline(signed_policy)
        signed_policy.write_text("tampered!")
        ok, msg = pi.check_integrity(signed_policy)
        assert ok is False

    def test_check_integrity_no_baseline(self, signing_key: bytes) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        ok, msg = pi.check_integrity("/some/path.yaml")
        assert ok is False
        assert "no baseline" in msg


class TestPackageExports:
    def test_policy_integrity_importable_from_core(self) -> None:
        from avakill.core.integrity import FileSnapshot, PolicyIntegrity

        assert PolicyIntegrity is not None
        assert FileSnapshot is not None

    def test_policy_integrity_lazy_import(self) -> None:
        import avakill

        pi = avakill.PolicyIntegrity
        from avakill.core.integrity import PolicyIntegrity as direct

        assert pi is direct


# --- Ed25519 signing tests (require PyNaCl) ---

nacl_signing = pytest.importorskip("nacl.signing")


@pytest.fixture
def ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair, returning (private_key, public_key) as raw bytes."""
    sk = nacl_signing.SigningKey.generate()
    return sk.encode(), sk.verify_key.encode()


@pytest.fixture
def ed25519_policy(tmp_path: Path) -> Path:
    """Create a valid policy file for Ed25519 tests."""
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


class TestEd25519Signing:
    def test_sign_creates_sidecar_with_prefix(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, _ = ed25519_keypair
        sig_path = PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        assert sig_path.exists()
        content = sig_path.read_text().strip()
        assert content.startswith("ed25519:")
        # Ed25519 signature is 64 bytes = 128 hex chars after prefix
        sig_hex = content[len("ed25519:") :]
        assert len(sig_hex) == 128
        bytes.fromhex(sig_hex)  # should not raise

    def test_verify_valid_ed25519_signature(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is True

    def test_verify_tampered_content_ed25519(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        ed25519_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is False

    def test_verify_bad_ed25519_signature(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        sig_path = Path(str(ed25519_policy) + ".sig")
        sig_path.write_text("ed25519:" + "00" * 64)
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is False

    def test_verify_wrong_public_key(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, _ = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        # Generate a different keypair
        other_sk = nacl_signing.SigningKey.generate()
        wrong_public = other_sk.verify_key.encode()
        assert PolicyIntegrity.verify_file(ed25519_policy, wrong_public) is False

    def test_verify_missing_sidecar_ed25519(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        _, public_key = ed25519_keypair
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is False

    def test_autodetect_hmac_vs_ed25519(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        """verify_file auto-detects based on signature prefix."""
        private_key, public_key = ed25519_keypair
        hmac_key = bytes.fromhex("dd" * 32)

        # First sign with HMAC
        PolicyIntegrity.sign_file(ed25519_policy, hmac_key)
        assert PolicyIntegrity.verify_file(ed25519_policy, hmac_key) is True
        # HMAC sig should not verify with Ed25519 key
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is False

        # Now sign with Ed25519
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        assert PolicyIntegrity.verify_file(ed25519_policy, public_key) is True
        # Ed25519 sig should not verify with HMAC key
        assert PolicyIntegrity.verify_file(ed25519_policy, hmac_key) is False


class TestEd25519LoadVerified:
    def test_load_verified_with_ed25519(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        pi = PolicyIntegrity(verify_key=public_key)
        config = pi.load_verified(ed25519_policy)
        assert isinstance(config, PolicyConfig)
        assert config.version == "1.0"
        assert len(config.policies) == 1

    def test_rejects_tampered_ed25519_signed_policy(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        # Tamper
        ed25519_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        pi = PolicyIntegrity(verify_key=public_key)
        config = pi.load_verified(ed25519_policy)
        assert config.default_action == "deny"  # deny-all fallback

    def test_rejects_unsigned_when_verify_key_set(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        _, public_key = ed25519_keypair
        pi = PolicyIntegrity(verify_key=public_key)
        config = pi.load_verified(ed25519_policy)
        assert config.default_action == "deny"  # signature file missing

    def test_ed25519_falls_back_to_last_known_good(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_key, public_key = ed25519_keypair
        PolicyIntegrity.sign_file_ed25519(ed25519_policy, private_key)
        pi = PolicyIntegrity(verify_key=public_key)
        good = pi.load_verified(ed25519_policy)
        assert len(good.policies) == 1

        # Tamper
        ed25519_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        fallback = pi.load_verified(ed25519_policy)
        assert len(fallback.policies) == 1  # last-known-good

    def test_hmac_sig_with_only_verify_key_falls_back(
        self, ed25519_policy: Path, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        """If an HMAC sig is present but only verify_key is set, should fall back."""
        _, public_key = ed25519_keypair
        hmac_key = bytes.fromhex("dd" * 32)
        PolicyIntegrity.sign_file(ed25519_policy, hmac_key)
        pi = PolicyIntegrity(verify_key=public_key)
        config = pi.load_verified(ed25519_policy)
        assert config.default_action == "deny"  # HMAC sig but no HMAC key

    def test_signing_enabled_with_verify_key(self, ed25519_keypair: tuple[bytes, bytes]) -> None:
        _, public_key = ed25519_keypair
        pi = PolicyIntegrity(verify_key=public_key)
        assert pi.signing_enabled is True

    def test_signing_enabled_without_keys(self) -> None:
        pi = PolicyIntegrity()
        assert pi.signing_enabled is False
