"""Tests for the AvaKill PolicyIntegrity module."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from avakill.core.integrity import FileSnapshot, PolicyIntegrity


class TestFileSnapshot:
    def test_create_from_path(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("version: '1.0'\n")
        snap = FileSnapshot.from_path(str(p))
        assert snap.path == os.path.realpath(str(p))
        assert snap.size > 0
        assert snap.sha256 == hashlib.sha256(b"version: '1.0'\n").hexdigest()

    def test_stat_precheck_unchanged(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("hello")
        snap = FileSnapshot.from_path(str(p))
        ok, msg = snap.verify(str(p))
        assert ok is True
        assert "stat pre-check" in msg

    def test_detects_content_change(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yaml"
        p.write_text("original")
        snap = FileSnapshot.from_path(str(p))
        p.write_text("tampered")
        ok, msg = snap.verify(str(p))
        assert ok is False
        assert "hash mismatch" in msg

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
        p.write_text("original")
        snap = FileSnapshot.from_path(str(p))
        # Replace: delete and recreate (new inode)
        p.unlink()
        p.write_text("original")  # same content, different inode
        ok, msg = snap.verify(str(p))
        assert ok is False
        assert "inode" in msg.lower()

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


from avakill.core.models import PolicyConfig


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
    def test_loads_valid_signed_policy(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(signed_policy)
        assert isinstance(config, PolicyConfig)
        assert config.version == "1.0"
        assert len(config.policies) == 1

    def test_rejects_unsigned_when_key_set(
        self, tmp_path: Path, signing_key: bytes
    ) -> None:
        p = tmp_path / "unsigned.yaml"
        p.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies: []\n"
        )
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

    def test_rejects_tampered_signed_policy(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
        # Tamper with content after signing
        signed_policy.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies: []\n"
        )
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
        signed_policy.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies: []\n"
        )
        # Should fall back to last-known-good
        fallback = pi.load_verified(signed_policy)
        assert len(fallback.policies) == 1  # still the good policy

    def test_invalid_yaml_falls_back(
        self, tmp_path: Path, signing_key: bytes
    ) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("{{not: valid: yaml::")
        # Sign the bad content (signature is valid but content isn't YAML)
        PolicyIntegrity.sign_file(p, signing_key)
        pi = PolicyIntegrity(signing_key=signing_key)
        config = pi.load_verified(p)
        assert config.default_action == "deny"  # deny-all fallback

    def test_invalid_schema_falls_back(
        self, tmp_path: Path, signing_key: bytes
    ) -> None:
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

    def test_get_last_known_good_after_load(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
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

    def test_check_integrity_unchanged(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
        pi = PolicyIntegrity(signing_key=signing_key)
        pi.set_baseline(signed_policy)
        ok, msg = pi.check_integrity(signed_policy)
        assert ok is True

    def test_check_integrity_tampered(
        self, signed_policy: Path, signing_key: bytes
    ) -> None:
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
        from avakill.core.integrity import PolicyIntegrity, FileSnapshot
        assert PolicyIntegrity is not None
        assert FileSnapshot is not None

    def test_policy_integrity_lazy_import(self) -> None:
        import avakill
        pi = avakill.PolicyIntegrity
        from avakill.core.integrity import PolicyIntegrity as direct
        assert pi is direct
