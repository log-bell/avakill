"""Automatic policy file watcher with hot-reload support.

Watches the policy YAML file for changes and triggers ``Guard.reload_policy()``
automatically.  Uses the ``watchfiles`` library (Rust-backed, async-native) when
available, falling back to pure-Python polling when it is not installed or when
forced via the ``AVAKILL_WATCH_POLL`` environment variable.

Install the optional extra::

    pip install avakill[watch]
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import signal
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from avakill.core.models import AuditEvent, Decision, ToolCall
from avakill.logging.event_bus import EventBus
from avakill.metrics import (
    inc_reload_failures,
    inc_reloads,
    set_reload_last_success,
)

if TYPE_CHECKING:
    from avakill.core.engine import Guard

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional import — watchfiles is a Rust-backed async file watcher
# ---------------------------------------------------------------------------
try:
    from watchfiles import awatch

    HAS_WATCHFILES = True
except ImportError:  # pragma: no cover
    HAS_WATCHFILES = False
    awatch = None  # type: ignore[assignment]

_RELOAD_TOOL = "__avakill_policy_reload__"


def _file_hash(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_reload_event(*, success: bool, trigger: str, error: str | None = None) -> AuditEvent:
    """Create a synthetic AuditEvent for a policy reload."""
    action = "allow" if success else "deny"
    reason = f"policy reload via {trigger}"
    if error:
        reason = f"{reason}: {error}"
    return AuditEvent(
        tool_call=ToolCall(
            tool_name=_RELOAD_TOOL,
            arguments={"trigger": trigger, "success": success},
        ),
        decision=Decision(
            allowed=success,
            action=action,
            policy_name="policy-reload",
            reason=reason,
        ),
    )


class PolicyWatcher:
    """Watches a policy file and triggers hot-reload on changes.

    Supports two modes:
    - **Native:** Uses ``watchfiles.awatch()`` with debounce (requires ``watchfiles``)
    - **Polling:** Pure-Python fallback using periodic stat + hash check

    The watcher can be used as an async context manager::

        async with PolicyWatcher(guard) as watcher:
            await asyncio.sleep(3600)  # watcher runs in background

    Or started/stopped manually::

        watcher = PolicyWatcher(guard)
        await watcher.start()
        ...
        await watcher.stop()
    """

    def __init__(
        self,
        guard: Guard,
        *,
        debounce_ms: int = 2000,
        cooldown_ms: int = 5000,
        poll_interval_s: float = 2.0,
        force_polling: bool | None = None,
        sighup: bool = True,
    ) -> None:
        if guard._policy_path is None:
            raise ValueError(
                "PolicyWatcher requires a file-based policy. "
                "Pass a file path to Guard(policy=...)"
            )

        self._guard = guard
        self._policy_path = guard._policy_path.resolve()
        self._debounce_ms = debounce_ms
        self._cooldown_ms = cooldown_ms
        self._poll_interval_s = poll_interval_s
        self._sighup = sighup
        self._event_bus = EventBus.get()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._last_reload: float = 0.0
        self._last_hash: str = ""
        self._stopped = False

        # Determine watch mode
        if force_polling is None:
            force_polling = os.environ.get("AVAKILL_WATCH_POLL", "").strip() in ("1", "true", "yes")
        self._use_polling = force_polling or not HAS_WATCHFILES

        # Compute initial hash
        with contextlib.suppress(OSError):
            self._last_hash = _file_hash(self._policy_path)

    @property
    def use_polling(self) -> bool:
        """Whether the watcher is using polling mode."""
        return self._use_polling

    @property
    def policy_path(self) -> Path:
        """The resolved path to the watched policy file."""
        return self._policy_path

    async def start(self) -> None:
        """Start the background watcher task."""
        if self._task is not None:
            raise RuntimeError("PolicyWatcher is already running")
        self._stopped = False

        loop = asyncio.get_running_loop()

        # Install SIGHUP handler (Unix only)
        if self._sighup and hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(signal.SIGHUP, self._on_sighup)

        if self._use_polling:
            self._task = asyncio.ensure_future(self._poll_loop())
        else:
            self._task = asyncio.ensure_future(self._native_loop())

        _logger.info(
            "PolicyWatcher started (%s mode) for %s",
            "polling" if self._use_polling else "native",
            self._policy_path,
        )

    async def stop(self) -> None:
        """Stop the background watcher task."""
        self._stopped = True

        # Remove SIGHUP handler
        if self._sighup and hasattr(signal, "SIGHUP"):
            with contextlib.suppress(Exception):
                loop = asyncio.get_running_loop()
                loop.remove_signal_handler(signal.SIGHUP)

        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        _logger.info("PolicyWatcher stopped")

    async def __aenter__(self) -> PolicyWatcher:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # SIGHUP handler
    # ------------------------------------------------------------------

    def _on_sighup(self) -> None:
        """Handle SIGHUP signal by scheduling a reload."""
        _logger.info("Received SIGHUP, scheduling policy reload")
        asyncio.ensure_future(self._do_reload("sighup"))

    # ------------------------------------------------------------------
    # Watch loops
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        """Pure-Python polling loop: stat + hash check."""
        while not self._stopped:
            try:
                await asyncio.sleep(self._poll_interval_s)
                if self._stopped:
                    break
                await self._check_and_reload("poll")
            except asyncio.CancelledError:
                break
            except Exception:
                _logger.exception("Error in polling loop")

    async def _native_loop(self) -> None:
        """watchfiles-backed native filesystem event loop."""
        # Build list of paths to watch — include .sig file if it exists
        watch_paths = [self._policy_path]
        sig_path = self._policy_path.with_suffix(self._policy_path.suffix + ".sig")
        if sig_path.exists():
            watch_paths.append(sig_path)

        try:
            async for _changes in awatch(  # type: ignore[misc]
                *watch_paths,
                debounce=self._debounce_ms,
                stop_event=None,
            ):
                if self._stopped:
                    break
                await self._check_and_reload("native")
        except asyncio.CancelledError:
            pass
        except Exception:
            _logger.exception("Error in native watch loop")

    # ------------------------------------------------------------------
    # Reload logic
    # ------------------------------------------------------------------

    async def _check_and_reload(self, trigger: str) -> None:
        """Check if the policy file changed and reload if necessary."""
        async with self._lock:
            # Cooldown check
            now = time.monotonic()
            elapsed_ms = (now - self._last_reload) * 1000
            if self._last_reload > 0 and elapsed_ms < self._cooldown_ms:
                _logger.debug(
                    "Reload cooldown active (%.0fms remaining)",
                    self._cooldown_ms - elapsed_ms,
                )
                return

            # Hash check — skip reload if content unchanged
            try:
                current_hash = _file_hash(self._policy_path)
            except OSError as exc:
                _logger.warning("Cannot read policy file: %s", exc)
                return

            if current_hash == self._last_hash:
                _logger.debug("Policy file unchanged (hash match), skipping reload")
                return

            await self._do_reload_inner(trigger, current_hash)

    async def _do_reload(self, trigger: str) -> None:
        """Force a reload attempt (used by SIGHUP handler)."""
        async with self._lock:
            try:
                current_hash = _file_hash(self._policy_path)
            except OSError as exc:
                _logger.warning("Cannot read policy file for %s reload: %s", trigger, exc)
                return
            await self._do_reload_inner(trigger, current_hash)

    async def _do_reload_inner(self, trigger: str, current_hash: str) -> None:
        """Execute the actual reload. Caller must hold ``self._lock``."""
        inc_reloads(trigger)

        try:
            self._guard.reload_policy()
            self._last_hash = current_hash
            self._last_reload = time.monotonic()
            ts = time.time()
            set_reload_last_success(ts)
            _logger.info("Policy reloaded successfully (trigger=%s)", trigger)
            event = _make_reload_event(success=True, trigger=trigger)
            self._event_bus.emit(event)
        except Exception as exc:
            inc_reload_failures(trigger)
            _logger.error("Policy reload failed (trigger=%s): %s", trigger, exc)
            event = _make_reload_event(success=False, trigger=trigger, error=str(exc))
            self._event_bus.emit(event)
