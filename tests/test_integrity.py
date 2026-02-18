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
