"""Tests for the synchronous AvaKill daemon client."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

import pytest

from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig
from avakill.daemon.client import DaemonClient
from avakill.daemon.protocol import EvaluateRequest
from avakill.daemon.server import DaemonServer
from avakill.logging.event_bus import EventBus

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Unix domain sockets not available on Windows",
)


@pytest.fixture(autouse=True)
def _reset_event_bus() -> None:
    EventBus.reset()
    yield  # type: ignore[misc]
    EventBus.reset()


@pytest.fixture
def socket_path() -> Path:
    d = tempfile.mkdtemp(prefix="ak_", dir=tempfile.gettempdir())
    yield Path(d) / "ak.sock"
    import shutil

    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def pid_path(tmp_path: Path) -> Path:
    return tmp_path / "avakill.pid"


@pytest.fixture
def guard(sample_policy: PolicyConfig) -> Guard:
    return Guard(policy=sample_policy, self_protection=False)


class TestDaemonClient:
    """Synchronous client evaluation and error handling.

    The sync client uses blocking sockets, so it must run in a thread
    to avoid blocking the event loop that the async server needs.
    """

    async def test_evaluate_allowed(self, guard: Guard, socket_path: Path, pid_path: Path) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            client = DaemonClient(socket_path=socket_path)
            resp = await asyncio.to_thread(
                client.evaluate, EvaluateRequest(agent="test", tool="file_read")
            )
            assert resp.decision == "allow"
        finally:
            await server.stop()

    async def test_evaluate_denied(self, guard: Guard, socket_path: Path, pid_path: Path) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            client = DaemonClient(socket_path=socket_path)
            resp = await asyncio.to_thread(
                client.evaluate, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.decision == "deny"
        finally:
            await server.stop()

    def test_connection_refused_returns_deny(self, socket_path: Path) -> None:
        client = DaemonClient(socket_path=socket_path, timeout=0.5)
        resp = client.evaluate(EvaluateRequest(agent="test", tool="file_read"))
        assert resp.decision == "deny"
        assert "daemon unavailable" in (resp.reason or "")

    async def test_ping_running_daemon(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            client = DaemonClient(socket_path=socket_path)
            result = await asyncio.to_thread(client.ping)
            assert result is True
        finally:
            await server.stop()

    def test_ping_no_daemon_returns_false(self, socket_path: Path) -> None:
        client = DaemonClient(socket_path=socket_path, timeout=0.5)
        assert client.ping() is False

    async def test_evaluate_returns_policy_name(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            client = DaemonClient(socket_path=socket_path)
            resp = await asyncio.to_thread(
                client.evaluate, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.policy == "deny-delete"
        finally:
            await server.stop()
