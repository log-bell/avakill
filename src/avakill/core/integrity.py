"""Policy integrity: file integrity monitoring, HMAC signing, and fail-closed loading."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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
            return False, f"content hash mismatch: expected {self.sha256[:16]}..., got {sha[:16]}..."
        return True, "ok (hash verified)"


class PolicyIntegrity:
    """Manages policy file integrity: signing, verification, and fail-closed loading."""

    def __init__(self, signing_key: bytes | None = None) -> None:
        self._signing_key = signing_key
        self._baseline: FileSnapshot | None = None

    @property
    def signing_enabled(self) -> bool:
        """Whether HMAC signing is active."""
        return self._signing_key is not None

    @staticmethod
    def sign_file(path: str | Path, key: bytes) -> Path:
        """Sign a policy file, creating a .sig sidecar.

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
    def verify_file(path: str | Path, key: bytes) -> bool:
        """Verify a policy file's HMAC signature.

        Args:
            path: Path to the policy YAML file.
            key: 32-byte HMAC signing key.

        Returns:
            True if signature is valid, False otherwise.
        """
        path = Path(path)
        sig_path = Path(str(path) + ".sig")
        if not sig_path.exists():
            return False
        content = path.read_bytes()
        expected = hmac.new(key, content, hashlib.sha256).hexdigest()
        actual = sig_path.read_text().strip()
        return hmac.compare_digest(expected, actual)
