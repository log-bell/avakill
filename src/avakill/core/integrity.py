"""Policy integrity: file integrity monitoring, HMAC/Ed25519 signing, and fail-closed loading."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from avakill.core.models import PolicyConfig

logger = logging.getLogger(__name__)

# Optional Ed25519 support via PyNaCl
try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey

    HAS_NACL = True
except ImportError:  # pragma: no cover
    HAS_NACL = False

_ED25519_PREFIX = "ed25519:"

_DENY_ALL = PolicyConfig(
    version="1.0",
    default_action="deny",
    policies=[],
)


@dataclass(frozen=True)
class FileSnapshot:
    """Immutable snapshot of a file's state for integrity verification."""

    path: str
    sha256: str
    size: int
    mtime_ns: int
    inode: int
    device: int
    mode: int
    uid: int
    gid: int

    @classmethod
    def from_path(cls, path: str) -> FileSnapshot:
        """Create a snapshot from the current state of a file."""
        real = os.path.realpath(path)
        st = os.stat(real)
        with open(real, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        return cls(
            path=real,
            sha256=sha,
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            inode=st.st_ino,
            device=st.st_dev,
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
        )

    def verify(self, path: str) -> tuple[bool, str]:
        """Verify a file against this baseline snapshot.

        Returns:
            A (ok, message) tuple. ok is True if the file is unchanged.
        """
        real = os.path.realpath(path)
        if real != self.path:
            return False, f"path redirected: expected {self.path}, got {real}"

        st = os.stat(real)

        if st.st_ino != self.inode or st.st_dev != self.device:
            return False, "inode/device changed (file replaced)"

        if st.st_mode != self.mode:
            return False, f"mode changed: expected {oct(self.mode)}, got {oct(st.st_mode)}"

        if st.st_uid != self.uid or st.st_gid != self.gid:
            return False, "ownership changed"

        # Fast path: skip hash if metadata unchanged
        if st.st_mtime_ns == self.mtime_ns and st.st_size == self.size:
            return True, "ok (stat pre-check)"

        # Slow path: metadata changed, verify hash
        with open(real, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        if sha != self.sha256:
            return False, (
                f"content hash mismatch: expected {self.sha256[:16]}..., got {sha[:16]}..."
            )
        return True, "ok (hash verified)"


class PolicyIntegrity:
    """Manages policy file integrity: signing, verification, and fail-closed loading."""

    def __init__(
        self,
        signing_key: bytes | None = None,
        verify_key: bytes | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._verify_key = verify_key
        self._baseline: FileSnapshot | None = None
        self._last_known_good: PolicyConfig | None = None

        if verify_key is not None and not HAS_NACL:
            logger.warning(
                "Ed25519 verify key provided but PyNaCl is not installed. "
                "Falling back to HMAC verification. "
                "Install with: pip install avakill[signed-policies]"
            )
            self._verify_key = None

    @property
    def signing_enabled(self) -> bool:
        """Whether signing (HMAC or Ed25519) is active."""
        return self._signing_key is not None or self._verify_key is not None

    def load_verified(self, path: str | Path) -> PolicyConfig:
        """Load a policy file with TOCTOU-safe verification.

        If signing is enabled, verifies the HMAC signature before parsing.
        On any failure, falls back to last-known-good or deny-all.

        Args:
            path: Path to the policy YAML file.

        Returns:
            A verified PolicyConfig, or a fallback.
        """
        import yaml
        from pydantic import ValidationError

        path = Path(path)

        # Step 1: Read file into memory (single read, TOCTOU-safe)
        try:
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                raw = b""
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    raw += chunk
            finally:
                os.close(fd)
        except OSError as exc:
            return self._fallback(f"cannot read file: {exc}")

        # Step 2: Verify signature if signing is enabled
        if self._signing_key is not None or self._verify_key is not None:
            sig_path = Path(str(path) + ".sig")
            if not sig_path.exists():
                return self._fallback("signature file missing")
            try:
                actual_sig = sig_path.read_text().strip()
            except OSError as exc:
                return self._fallback(f"cannot read signature: {exc}")

            # Auto-detect signature type
            if actual_sig.startswith(_ED25519_PREFIX):
                # Ed25519 verification
                if self._verify_key is None:
                    return self._fallback("Ed25519 signature found but no verify key configured")
                sig_hex = actual_sig[len(_ED25519_PREFIX) :]
                try:
                    vk = VerifyKey(self._verify_key)
                    vk.verify(raw, bytes.fromhex(sig_hex))
                except (BadSignatureError, ValueError, Exception) as exc:
                    return self._fallback(f"Ed25519 signature invalid: {exc}")
            else:
                # HMAC verification
                if self._signing_key is None:
                    return self._fallback("HMAC signature found but no HMAC key configured")
                expected_sig = hmac.new(self._signing_key, raw, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_sig, actual_sig):
                    return self._fallback("HMAC signature mismatch")

        # Step 3: Parse the verified bytes (never re-read file)
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            return self._fallback(f"invalid YAML: {exc}")

        if not isinstance(data, dict):
            return self._fallback("policy file is not a YAML mapping")

        # Step 4: Validate schema
        try:
            config = PolicyConfig(**data)
        except (ValidationError, ValueError) as exc:
            return self._fallback(f"schema validation failed: {exc}")

        # Step 5: Cache as last-known-good
        self._last_known_good = config

        # Step 6: Set baseline for ongoing integrity checks
        import contextlib

        with contextlib.suppress(OSError):
            self._baseline = FileSnapshot.from_path(str(path))

        logger.info("Policy loaded and verified: %s", path)
        return config

    def set_baseline(self, path: str | Path) -> FileSnapshot:
        """Set the FIM baseline for a policy file.

        Args:
            path: Path to the policy file.

        Returns:
            The baseline FileSnapshot.
        """
        self._baseline = FileSnapshot.from_path(str(path))
        return self._baseline

    def check_integrity(self, path: str | Path) -> tuple[bool, str]:
        """Check policy file integrity against the stored baseline.

        Returns:
            A (ok, message) tuple.
        """
        if self._baseline is None:
            return False, "no baseline set"
        return self._baseline.verify(str(path))

    def get_last_known_good(self) -> PolicyConfig | None:
        """Return the last successfully verified policy, or None."""
        return self._last_known_good

    def _fallback(self, reason: str) -> PolicyConfig:
        """Return last-known-good or deny-all on verification failure."""
        if self._last_known_good is not None:
            logger.warning("Using last-known-good policy (%s)", reason)
            return self._last_known_good
        logger.critical("No fallback available — DENY ALL (%s)", reason)
        return _DENY_ALL

    @staticmethod
    def sign_file(path: str | Path, key: bytes) -> Path:
        """Sign a policy file with HMAC-SHA256, creating a .sig sidecar.

        Args:
            path: Path to the policy YAML file.
            key: 32-byte HMAC signing key.

        Returns:
            Path to the created .sig file.
        """
        path = Path(path)
        content = path.read_bytes()
        sig = hmac.new(key, content, hashlib.sha256).hexdigest()
        sig_path = Path(str(path) + ".sig")
        sig_path.write_text(sig)
        return sig_path

    @staticmethod
    def sign_file_ed25519(path: str | Path, private_key: bytes) -> Path:
        """Sign a policy file with Ed25519, creating a .sig sidecar.

        Args:
            path: Path to the policy YAML file.
            private_key: 32-byte Ed25519 private (signing) key.

        Returns:
            Path to the created .sig file.

        Raises:
            RuntimeError: If PyNaCl is not installed.
        """
        if not HAS_NACL:
            raise RuntimeError(
                "PyNaCl is required for Ed25519 signing. "
                "Install with: pip install avakill[signed-policies]"
            )
        path = Path(path)
        content = path.read_bytes()
        sk = SigningKey(private_key)
        signed = sk.sign(content)
        sig_hex = signed.signature.hex()
        sig_path = Path(str(path) + ".sig")
        sig_path.write_text(f"{_ED25519_PREFIX}{sig_hex}")
        return sig_path

    @staticmethod
    def verify_file(path: str | Path, key: bytes) -> bool:
        """Verify a policy file's signature, auto-detecting HMAC or Ed25519.

        For HMAC signatures, ``key`` is the shared HMAC key.
        For Ed25519 signatures (prefixed with ``ed25519:``), ``key`` is
        the 32-byte public (verify) key.

        Args:
            path: Path to the policy YAML file.
            key: Signing/verify key bytes (type depends on signature format).

        Returns:
            True if signature is valid, False otherwise.
        """
        path = Path(path)
        sig_path = Path(str(path) + ".sig")
        if not sig_path.exists():
            return False
        content = path.read_bytes()
        actual = sig_path.read_text().strip()

        if actual.startswith(_ED25519_PREFIX):
            if not HAS_NACL:
                logger.warning("Ed25519 signature found but PyNaCl is not installed")
                return False
            sig_hex = actual[len(_ED25519_PREFIX) :]
            try:
                vk = VerifyKey(key)
                vk.verify(content, bytes.fromhex(sig_hex))
                return True
            except Exception:
                return False

        # HMAC verification (default)
        expected = hmac.new(key, content, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, actual)
