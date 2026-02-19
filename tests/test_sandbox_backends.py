"""Tests for SandboxBackend protocol and NoopSandboxBackend."""

from __future__ import annotations

from avakill.core.models import SandboxConfig
from avakill.launcher.backends.base import SandboxBackend, get_sandbox_backend
from avakill.launcher.backends.noop import NoopSandboxBackend


class TestSandboxBackendProtocol:
    def test_noop_implements_protocol(self):
        backend = NoopSandboxBackend()
        assert isinstance(backend, SandboxBackend)

    def test_get_sandbox_backend_returns_backend(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "freebsd")
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
