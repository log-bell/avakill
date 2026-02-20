"""Integration tests for platform-specific sandbox backends.

Tests marked with platform-specific skipif decorators. Each test
launches a real subprocess and verifies sandbox restrictions work.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from avakill.core.models import SandboxConfig, SandboxPathRules
from avakill.launcher.backends.base import get_sandbox_backend


class TestSandboxBackendAutoDetection:
    def test_returns_landlock_on_linux(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = get_sandbox_backend()
        assert type(backend).__name__ == "LandlockBackend"

    def test_returns_darwin_on_macos(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        backend = get_sandbox_backend()
        assert type(backend).__name__ == "MacOSSandboxBackend"

    def test_returns_windows_on_win32(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        backend = get_sandbox_backend()
        assert type(backend).__name__ == "WindowsSandboxBackend"

    def test_returns_noop_on_unknown(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "freebsd")
        backend = get_sandbox_backend()
        assert type(backend).__name__ == "NoopSandboxBackend"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only")
class TestDarwinSandboxIntegration:
    def test_sandbox_init_available(self):
        """Verify sandbox_init_with_parameters is callable on this macOS."""
        import ctypes

        libsystem = ctypes.CDLL("libSystem.dylib")
        assert hasattr(libsystem, "sandbox_init_with_parameters")

    def test_sandboxed_child_cannot_write_outside_allowed(self, tmp_path):
        from avakill.launcher.backends.darwin_backend import DarwinSandboxBackend

        backend = DarwinSandboxBackend()
        (tmp_path / "allowed").mkdir()
        forbidden = tmp_path / "forbidden"
        forbidden.mkdir()

        config = SandboxConfig(
            allow_paths=SandboxPathRules(
                read=["/usr", "/bin", "/lib", "/private", "/System", "/dev"],
                write=[str(tmp_path / "allowed")],
                execute=["/bin/sh", "/usr/bin/touch"],
            ),
        )

        preexec = backend.prepare_preexec(config)
        assert preexec is not None

        result = subprocess.run(
            ["/bin/sh", "-c", f"/usr/bin/touch '{forbidden}/test.txt'"],
            preexec_fn=preexec,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0

    def test_describe_reports_darwin_sandbox(self):
        """Verify dry-run report includes macOS sandbox details."""
        from avakill.launcher.backends.darwin_backend import DarwinSandboxBackend

        backend = DarwinSandboxBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(
                read=["/usr"],
                write=["/tmp"],
                execute=["/bin/sh"],
            ),
        )
        report = backend.describe(config)
        assert report["platform"] == "darwin"
        assert report["sandbox_applied"] is True
        assert report["mechanism"] == "sandbox_init_with_parameters"
        assert "(deny default)" in report["sbpl_profile"]
        assert "file-read*" in report["sbpl_profile"]
        assert "file-write*" in report["sbpl_profile"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestLandlockIntegration:
    def test_landlock_available(self):
        from avakill.enforcement.landlock import LandlockEnforcer

        LandlockEnforcer.available()
