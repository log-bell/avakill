"""Tests for SandboxBackend protocol and platform backends."""

from __future__ import annotations

import sys

import pytest

from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    SandboxConfig,
    SandboxNetworkRules,
    SandboxPathRules,
    SandboxResourceLimits,
)
from avakill.launcher.backends.base import SandboxBackend, get_sandbox_backend
from avakill.launcher.backends.darwin_backend import DarwinSandboxBackend
from avakill.launcher.backends.landlock_backend import LandlockBackend
from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend
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

    @pytest.mark.skipif(sys.platform == "win32", reason="Landlock requires Linux kernel")
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


class TestMacOSSandboxBackendModes:
    """Tests for MacOSSandboxBackend allow-based vs deny-based mode switching."""

    def _policy_with_sandbox(self, allow_paths=None, deny_rules=False):
        policies = []
        if deny_rules:
            policies.append(PolicyRule(name="deny-write", tools=["file_write"], action="deny"))
        sandbox = None
        if allow_paths is not None:
            sandbox = SandboxConfig(allow_paths=allow_paths)
        return PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=policies,
            sandbox=sandbox,
        )

    def test_allow_based_mode_when_allow_paths_present(self, monkeypatch):
        """When sandbox.allow_paths has entries, use allow-based (deny-default) mode."""
        monkeypatch.setattr("sys.platform", "darwin")
        policy = self._policy_with_sandbox(
            allow_paths=SandboxPathRules(read=["/usr"], write=["/tmp"]),
        )
        backend = MacOSSandboxBackend(policy)
        profile = backend.get_profile_content()
        assert "(deny default)" in profile
        assert backend._profile_mode == "allow-based"

    def test_deny_based_mode_when_no_allow_paths(self, monkeypatch):
        """When no sandbox section, fall back to deny-based (allow-default) mode."""
        monkeypatch.setattr("sys.platform", "darwin")
        policy = self._policy_with_sandbox(deny_rules=True)
        backend = MacOSSandboxBackend(policy)
        profile = backend.get_profile_content()
        assert "(allow default)" in profile
        assert backend._profile_mode == "deny-based"

    def test_deny_based_mode_when_empty_allow_paths(self, monkeypatch):
        """Empty allow_paths should still use deny-based mode."""
        monkeypatch.setattr("sys.platform", "darwin")
        policy = self._policy_with_sandbox(
            allow_paths=SandboxPathRules(),
            deny_rules=True,
        )
        backend = MacOSSandboxBackend(policy)
        profile = backend.get_profile_content()
        assert "(allow default)" in profile
        assert backend._profile_mode == "deny-based"

    def test_describe_includes_mode_and_paths(self, monkeypatch):
        """describe() should report mode and allowed paths in allow-based mode."""
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(
            "os.path.isfile",
            lambda p: p == "/usr/bin/sandbox-exec",
        )
        policy = self._policy_with_sandbox(
            allow_paths=SandboxPathRules(
                read=["/usr"],
                write=["/tmp"],
                execute=["/usr/bin/python3"],
            ),
        )
        backend = MacOSSandboxBackend(policy)
        report = backend.describe(policy.sandbox)
        assert report["mode"] == "allow-based"
        assert report["sandbox_applied"] is True
        assert "/usr" in report["allowed_read_paths"]
        assert "/tmp" in report["allowed_write_paths"]
        assert "/usr/bin/python3" in report["allowed_exec_paths"]

    def test_describe_deny_mode_no_path_lists(self, monkeypatch):
        """describe() in deny-based mode should not include allowed_*_paths."""
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(
            "os.path.isfile",
            lambda p: p == "/usr/bin/sandbox-exec",
        )
        policy = self._policy_with_sandbox(deny_rules=True)
        backend = MacOSSandboxBackend(policy)
        report = backend.describe(SandboxConfig())
        assert report["mode"] == "deny-based"
        assert "allowed_read_paths" not in report

    def test_has_allow_paths_helper(self):
        """_has_allow_paths returns True only when paths are non-empty."""
        assert MacOSSandboxBackend._has_allow_paths(SandboxConfig()) is False
        assert (
            MacOSSandboxBackend._has_allow_paths(
                SandboxConfig(allow_paths=SandboxPathRules(read=["/usr"]))
            )
            is True
        )
        assert (
            MacOSSandboxBackend._has_allow_paths(
                SandboxConfig(allow_paths=SandboxPathRules(write=["/tmp"]))
            )
            is True
        )
        assert (
            MacOSSandboxBackend._has_allow_paths(
                SandboxConfig(allow_paths=SandboxPathRules(execute=["/bin/sh"]))
            )
            is True
        )

    def test_allow_based_profile_includes_network(self, monkeypatch):
        """Allow-based profile should include network rules when configured."""
        monkeypatch.setattr("sys.platform", "darwin")
        policy = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(read=["/usr"]),
                allow_network=SandboxNetworkRules(connect=["api.openai.com:443"]),
            ),
        )
        backend = MacOSSandboxBackend(policy)
        profile = backend.get_profile_content()
        assert "(allow network-outbound (remote tcp))" in profile
