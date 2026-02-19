"""Tests for SandboxBackend protocol and platform backends."""

from __future__ import annotations

from avakill.core.models import (
    SandboxConfig,
    SandboxPathRules,
    SandboxResourceLimits,
)
from avakill.launcher.backends.base import SandboxBackend, get_sandbox_backend
from avakill.launcher.backends.darwin_backend import DarwinSandboxBackend
from avakill.launcher.backends.landlock_backend import LandlockBackend
from avakill.launcher.backends.noop import NoopSandboxBackend
from avakill.launcher.backends.windows_backend import WindowsSandboxBackend


class TestSandboxBackendProtocol:
    def test_noop_implements_protocol(self):
        backend = NoopSandboxBackend()
        assert isinstance(backend, SandboxBackend)

    def test_get_sandbox_backend_returns_backend(self):
        backend = get_sandbox_backend()
        assert isinstance(backend, SandboxBackend)

    def test_get_sandbox_backend_returns_noop_on_unknown_platform(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "freebsd")
        from avakill.launcher.backends.base import get_sandbox_backend as gsb

        backend = gsb()
        assert isinstance(backend, NoopSandboxBackend)


class TestNoopSandboxBackend:
    def test_available_returns_true(self):
        backend = NoopSandboxBackend()
        assert backend.available() is True

    def test_prepare_preexec_returns_none(self):
        backend = NoopSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_preexec(config) is None

    def test_prepare_process_args_returns_empty_dict(self):
        backend = NoopSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_process_args(config) == {}

    def test_post_create_is_noop(self):
        backend = NoopSandboxBackend()
        config = SandboxConfig()
        backend.post_create(12345, config)

    def test_describe_returns_platform_info(self):
        backend = NoopSandboxBackend()
        config = SandboxConfig()
        report = backend.describe(config)
        assert report["platform"] == "unsupported"
        assert report["sandbox_applied"] is False


class TestLandlockBackend:
    def test_available_true_on_linux_with_landlock(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.available",
            staticmethod(lambda: True),
        )
        backend = LandlockBackend()
        assert backend.available() is True

    def test_available_false_on_non_linux(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        backend = LandlockBackend()
        assert backend.available() is False

    def test_prepare_preexec_returns_callable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.available",
            staticmethod(lambda: True),
        )
        backend = LandlockBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(
                read=["/usr", "/bin"],
                write=["/tmp"],
                execute=["/usr/bin/python3"],
            ),
        )
        fn = backend.prepare_preexec(config)
        assert callable(fn)

    def test_prepare_preexec_returns_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.available",
            staticmethod(lambda: False),
        )
        backend = LandlockBackend()
        config = SandboxConfig()
        assert backend.prepare_preexec(config) is None

    def test_prepare_process_args_returns_empty_dict(self):
        backend = LandlockBackend()
        config = SandboxConfig()
        assert backend.prepare_process_args(config) == {}

    def test_post_create_is_noop(self):
        backend = LandlockBackend()
        config = SandboxConfig()
        backend.post_create(12345, config)

    def test_describe_includes_abi_version(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.available",
            staticmethod(lambda: True),
        )
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.abi_version",
            staticmethod(lambda: 4),
        )
        backend = LandlockBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["/usr"]),
        )
        report = backend.describe(config)
        assert report["platform"] == "linux"
        assert report["sandbox_applied"] is True
        assert report["abi_version"] == 4
        assert "/usr" in report["allowed_read_paths"]

    def test_describe_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(
            "avakill.launcher.backends.landlock_backend.LandlockEnforcer.available",
            staticmethod(lambda: False),
        )
        backend = LandlockBackend()
        config = SandboxConfig()
        report = backend.describe(config)
        assert report["sandbox_applied"] is False


class TestDarwinSandboxBackend:
    def test_available_true_on_darwin(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        backend = DarwinSandboxBackend()
        assert backend.available() is True

    def test_available_false_on_non_darwin(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = DarwinSandboxBackend()
        assert backend.available() is False

    def test_prepare_preexec_returns_callable_on_darwin(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        backend = DarwinSandboxBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["/usr"]),
        )
        fn = backend.prepare_preexec(config)
        assert callable(fn)

    def test_prepare_preexec_returns_none_on_non_darwin(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = DarwinSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_preexec(config) is None

    def test_prepare_process_args_returns_empty_dict(self):
        backend = DarwinSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_process_args(config) == {}

    def test_describe_includes_sbpl_preview(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        backend = DarwinSandboxBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["/usr"], write=["/tmp"]),
        )
        report = backend.describe(config)
        assert report["platform"] == "darwin"
        assert report["sandbox_applied"] is True
        assert report["mechanism"] == "sandbox_init_with_parameters"
        assert "(deny default)" in report["sbpl_profile"]

    def test_describe_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = DarwinSandboxBackend()
        config = SandboxConfig()
        report = backend.describe(config)
        assert report["sandbox_applied"] is False


class TestWindowsSandboxBackend:
    def test_available_true_on_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        backend = WindowsSandboxBackend()
        assert backend.available() is True

    def test_available_false_on_non_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = WindowsSandboxBackend()
        assert backend.available() is False

    def test_prepare_preexec_returns_none(self):
        """Windows doesn't use preexec_fn."""
        backend = WindowsSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_preexec(config) is None

    def test_prepare_process_args_includes_creation_flags(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        backend = WindowsSandboxBackend()
        config = SandboxConfig()
        args = backend.prepare_process_args(config)
        assert "creationflags" in args

    def test_prepare_process_args_empty_on_non_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = WindowsSandboxBackend()
        config = SandboxConfig()
        assert backend.prepare_process_args(config) == {}

    def test_describe_includes_appcontainer_info(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        backend = WindowsSandboxBackend()
        config = SandboxConfig(
            allow_paths=SandboxPathRules(read=["C:\\Users\\me\\project"]),
        )
        report = backend.describe(config)
        assert report["platform"] == "windows"
        assert report["sandbox_applied"] is True
        assert report["mechanism"] == "appcontainer"

    def test_describe_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        backend = WindowsSandboxBackend()
        config = SandboxConfig()
        report = backend.describe(config)
        assert report["sandbox_applied"] is False

    def test_describe_includes_resource_limits(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        backend = WindowsSandboxBackend()
        config = SandboxConfig(
            resource_limits=SandboxResourceLimits(
                max_memory_mb=512,
                max_processes=10,
            ),
        )
        report = backend.describe(config)
        assert report["job_object"]["memory_limit_mb"] == 512
        assert report["job_object"]["process_limit"] == 10
