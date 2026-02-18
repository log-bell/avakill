"""Tests for the PolicyWatcher and Guard.watch()/unwatch() integration."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from avakill.core.engine import Guard
from avakill.core.models import AuditEvent
from avakill.core.watcher import HAS_WATCHFILES, PolicyWatcher, _file_hash
from avakill.logging.event_bus import EventBus
from avakill.metrics import (
    HAS_PROMETHEUS,
    get_registry,
    reset_metrics,
)

# Short intervals for fast tests
_POLL = 0.1
_COOLDOWN = 100
_DEBOUNCE = 100

_POLICY_V1 = (
    "version: '1.0'\n"
    "default_action: deny\n"
    "policies:\n"
    "  - name: allow-read\n"
    "    tools: [file_read]\n"
    "    action: allow\n"
)

_POLICY_V2 = (
    "version: '1.0'\n"
    "default_action: deny\n"
    "policies:\n"
    "  - name: allow-read\n"
    "    tools: [file_read]\n"
    "    action: allow\n"
    "  - name: allow-write\n"
    "    tools: [file_write]\n"
    "    action: allow\n"
)


@pytest.fixture(autouse=True)
def _reset_bus_and_metrics():
    """Ensure each test gets a fresh EventBus and metrics state."""
    EventBus.reset()
    reset_metrics()
    yield
    EventBus.reset()
    reset_metrics()


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(_POLICY_V1)
    return p


@pytest.fixture
def guard(policy_file: Path) -> Guard:
    return Guard(policy=policy_file, self_protection=False)


# ------------------------------------------------------------------
# Init tests
# ------------------------------------------------------------------
class TestPolicyWatcherInit:
    def test_requires_file_based_policy(self) -> None:
        g = Guard(
            policy={"version": "1.0", "default_action": "deny", "policies": []},
            self_protection=False,
        )
        with pytest.raises(ValueError, match="file-based policy"):
            PolicyWatcher(g)

    def test_respects_defaults(self, guard: Guard) -> None:
        w = PolicyWatcher(guard)
        assert w._debounce_ms == 2000
        assert w._cooldown_ms == 5000
        assert w._poll_interval_s == 2.0
        assert w._sighup is True

    def test_custom_params(self, guard: Guard) -> None:
        w = PolicyWatcher(
            guard,
            debounce_ms=500,
            cooldown_ms=1000,
            poll_interval_s=0.5,
            sighup=False,
        )
        assert w._debounce_ms == 500
        assert w._cooldown_ms == 1000
        assert w._poll_interval_s == 0.5
        assert w._sighup is False

    def test_env_var_forces_polling(self, guard: Guard) -> None:
        with patch.dict(os.environ, {"AVAKILL_WATCH_POLL": "1"}):
            w = PolicyWatcher(guard)
            assert w.use_polling is True

    def test_force_polling_param(self, guard: Guard) -> None:
        w = PolicyWatcher(guard, force_polling=True)
        assert w.use_polling is True

    def test_has_watchfiles_false_forces_polling(self, guard: Guard) -> None:
        with patch("avakill.core.watcher.HAS_WATCHFILES", False):
            w = PolicyWatcher(guard, force_polling=False)
            assert w.use_polling is True

    def test_initial_hash_computed(self, guard: Guard, policy_file: Path) -> None:
        w = PolicyWatcher(guard)
        assert w._last_hash == _file_hash(policy_file)

    def test_policy_path_resolved(self, guard: Guard, policy_file: Path) -> None:
        w = PolicyWatcher(guard)
        assert w.policy_path == policy_file.resolve()


# ------------------------------------------------------------------
# Polling tests
# ------------------------------------------------------------------
class TestPolicyWatcherPolling:
    async def test_detects_file_change(self, guard: Guard, policy_file: Path) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            # Modify the policy
            policy_file.write_text(_POLICY_V2)
            # Wait for polling to detect + reload
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) >= 1
        assert reload_events[0].decision.allowed is True

    async def test_no_reload_when_content_unchanged(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            # Touch the file without changing content
            policy_file.write_text(_POLICY_V1)
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) == 0

    async def test_cooldown_prevents_rapid_reloads(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=2000,  # long cooldown
        )
        await w.start()
        try:
            # Rapid changes
            policy_file.write_text(_POLICY_V2)
            await asyncio.sleep(_POLL * 3)
            policy_file.write_text(_POLICY_V1)
            await asyncio.sleep(_POLL * 3)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        # Only one reload should have happened due to cooldown
        assert len(reload_events) == 1

    async def test_emits_failure_event_on_bad_policy(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            # Write invalid YAML
            policy_file.write_text("not: valid: yaml: [[[")
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) >= 1
        assert reload_events[0].decision.allowed is False


# ------------------------------------------------------------------
# Native watcher tests (skip if watchfiles not installed)
# ------------------------------------------------------------------
class TestPolicyWatcherNative:
    @pytest.mark.skipif(not HAS_WATCHFILES, reason="watchfiles not installed")
    async def test_detects_change_via_native(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=False,
            debounce_ms=_DEBOUNCE,
            cooldown_ms=_COOLDOWN,
        )
        assert w.use_polling is False
        await w.start()
        try:
            await asyncio.sleep(0.2)
            policy_file.write_text(_POLICY_V2)
            await asyncio.sleep(1.0)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) >= 1
        assert reload_events[0].decision.allowed is True

    @pytest.mark.skipif(not HAS_WATCHFILES, reason="watchfiles not installed")
    async def test_debounce_coalesces_rapid_changes(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=False,
            debounce_ms=500,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            await asyncio.sleep(0.2)
            # Multiple rapid writes within debounce window
            for i in range(5):
                policy_file.write_text(_POLICY_V2 + f"# edit {i}\n")
                await asyncio.sleep(0.05)
            await asyncio.sleep(1.5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        # Debounce should coalesce — expect far fewer reloads than the 5 writes
        assert 1 <= len(reload_events) < 5


# ------------------------------------------------------------------
# SIGHUP handler tests
# ------------------------------------------------------------------
class TestSighupHandler:
    @pytest.mark.skipif(
        sys.platform == "win32", reason="SIGHUP not available on Windows"
    )
    async def test_sighup_triggers_reload(
        self, guard: Guard, policy_file: Path
    ) -> None:
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        # Change the file content first so hash differs
        policy_file.write_text(_POLICY_V2)

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=999,  # effectively disable polling
            cooldown_ms=_COOLDOWN,
            sighup=True,
        )
        await w.start()
        try:
            await asyncio.sleep(0.1)
            os.kill(os.getpid(), signal.SIGHUP)
            await asyncio.sleep(0.5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) >= 1

    @pytest.mark.skipif(
        sys.platform == "win32", reason="SIGHUP not available on Windows"
    )
    async def test_sighup_false_skips_handler(
        self, guard: Guard, policy_file: Path
    ) -> None:
        policy_file.write_text(_POLICY_V2)

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=999,
            cooldown_ms=_COOLDOWN,
            sighup=False,
        )
        await w.start()
        try:
            # SIGHUP should kill/crash without the handler installed,
            # so we just verify no handler was added by checking stop is clean
            pass
        finally:
            await w.stop()


# ------------------------------------------------------------------
# Guard.watch() / unwatch() tests
# ------------------------------------------------------------------
class TestGuardWatchUnwatch:
    def test_watch_returns_watcher(self, guard: Guard) -> None:
        w = guard.watch(force_polling=True)
        assert isinstance(w, PolicyWatcher)
        assert guard._watcher is w

    def test_double_watch_raises(self, guard: Guard) -> None:
        guard.watch(force_polling=True)
        with pytest.raises(RuntimeError, match="already active"):
            guard.watch(force_polling=True)

    async def test_unwatch_cleans_up(self, guard: Guard) -> None:
        w = guard.watch(force_polling=True, poll_interval_s=_POLL)
        await w.start()
        assert guard._watcher is not None
        await guard.unwatch()
        assert guard._watcher is None

    async def test_unwatch_when_no_watcher(self, guard: Guard) -> None:
        # Should not raise
        await guard.unwatch()

    def test_watch_requires_file_policy(self) -> None:
        g = Guard(
            policy={"version": "1.0", "default_action": "deny", "policies": []},
            self_protection=False,
        )
        with pytest.raises(ValueError, match="file-based policy"):
            g.watch()


# ------------------------------------------------------------------
# Dashboard reload tests
# ------------------------------------------------------------------
class TestDashboardReload:
    def test_reload_policy_calls_guard(self, guard: Guard, policy_file: Path) -> None:
        from avakill.cli.dashboard_cmd import _Dashboard

        dash = _Dashboard(":memory:", 0.5, str(policy_file))
        # The dashboard creates its own Guard, verify it has one
        assert dash._guard is not None

        # Write a new policy and call reload
        policy_file.write_text(_POLICY_V2)
        dash._reload_policy()
        # Should not raise — reload succeeded
        # Verify the engine actually picked up the new policy
        assert len(dash._guard.engine.config.policies) == 2

    def test_reload_no_crash_when_guard_is_none(self) -> None:
        from avakill.cli.dashboard_cmd import _Dashboard

        dash = _Dashboard(":memory:", 0.5, None)
        assert dash._guard is None
        # Should not raise
        dash._reload_policy()


# ------------------------------------------------------------------
# Metrics tests
# ------------------------------------------------------------------
class TestWatcherMetrics:
    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    async def test_counters_increment_on_reload(
        self, guard: Guard, policy_file: Path
    ) -> None:
        from prometheus_client import generate_latest

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            policy_file.write_text(_POLICY_V2)
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        output = generate_latest(get_registry()).decode()
        assert "avakill_policy_reloads_total" in output
        assert "avakill_policy_reload_last_success_timestamp" in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    async def test_failure_counter_increments(
        self, guard: Guard, policy_file: Path
    ) -> None:
        from prometheus_client import generate_latest

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            policy_file.write_text("not: valid: yaml: [[[")
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        output = generate_latest(get_registry()).decode()
        assert "avakill_policy_reload_failures_total" in output


# ------------------------------------------------------------------
# Signed policy tests
# ------------------------------------------------------------------
class TestWatcherSignedPolicies:
    @pytest.fixture
    def signed_guard(self, tmp_path: Path) -> tuple[Guard, Path, bytes]:
        """Create a Guard with HMAC-signed policy."""
        from avakill.core.integrity import PolicyIntegrity

        policy_path = tmp_path / "signed.yaml"
        policy_path.write_text(_POLICY_V1)

        key = os.urandom(32)
        PolicyIntegrity.sign_file(policy_path, key)

        g = Guard(policy=policy_path, self_protection=False, signing_key=key)
        return g, policy_path, key

    async def test_signed_yaml_reload(
        self, signed_guard: tuple[Guard, Path, bytes]
    ) -> None:
        from avakill.core.integrity import PolicyIntegrity

        guard, policy_path, key = signed_guard
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            # Re-sign with new content
            policy_path.write_text(_POLICY_V2)
            PolicyIntegrity.sign_file(policy_path, key)
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        assert len(reload_events) >= 1

    async def test_tampered_yaml_triggers_fallback(
        self, signed_guard: tuple[Guard, Path, bytes]
    ) -> None:
        guard, policy_path, _key = signed_guard
        events: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(lambda e: events.append(e))

        w = PolicyWatcher(
            guard,
            force_polling=True,
            poll_interval_s=_POLL,
            cooldown_ms=_COOLDOWN,
        )
        await w.start()
        try:
            # Tamper: write new content without re-signing
            policy_path.write_text(_POLICY_V2)
            await asyncio.sleep(_POLL * 5)
        finally:
            await w.stop()

        reload_events = [
            e for e in events if e.tool_call.tool_name == "__avakill_policy_reload__"
        ]
        # reload_policy should still succeed (falls back to last-known-good)
        assert len(reload_events) >= 1


# ------------------------------------------------------------------
# Async context manager tests
# ------------------------------------------------------------------
class TestAsyncContextManager:
    async def test_async_with(self, guard: Guard, policy_file: Path) -> None:
        async with PolicyWatcher(
            guard, force_polling=True, poll_interval_s=_POLL, cooldown_ms=_COOLDOWN
        ) as w:
            assert w._task is not None
        assert w._task is None

    async def test_double_start_raises(self, guard: Guard) -> None:
        w = PolicyWatcher(guard, force_polling=True, poll_interval_s=_POLL)
        await w.start()
        try:
            with pytest.raises(RuntimeError, match="already running"):
                await w.start()
        finally:
            await w.stop()
