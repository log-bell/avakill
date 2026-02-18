"""Tests for the AvaKill daemon server."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig, PolicyRule
from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_response,
    serialize_request,
)
from avakill.daemon.server import DaemonServer
from avakill.logging.event_bus import EventBus


@pytest.fixture(autouse=True)
def _reset_event_bus() -> None:
    EventBus.reset()
    yield  # type: ignore[misc]
    EventBus.reset()


@pytest.fixture
def socket_path() -> Path:
    # macOS AF_UNIX path limit is 104 bytes; pytest tmp_path is too long.
    # Use a short temp dir under /tmp instead.
    d = tempfile.mkdtemp(prefix="ak_", dir="/tmp")
    yield Path(d) / "ak.sock"
    import shutil

    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def pid_path(tmp_path: Path) -> Path:
    return tmp_path / "avakill.pid"


@pytest.fixture
def guard(sample_policy: PolicyConfig) -> Guard:
    return Guard(policy=sample_policy, self_protection=False)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


async def _send_request(
    socket_path: Path,
    req: EvaluateRequest,
) -> EvaluateResponse:
    """Connect to the daemon, send one request, return the response."""
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    writer.write(serialize_request(req))
    await writer.drain()
    writer.write_eof()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return deserialize_response(raw)


async def _send_raw(socket_path: Path, data: bytes) -> bytes:
    """Send raw bytes and return the raw response line."""
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    writer.write(data)
    await writer.drain()
    writer.write_eof()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return raw


# ------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------


class TestDaemonServerLifecycle:
    """Server start/stop and PID management."""

    async def test_start_creates_socket_file(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            assert socket_path.exists()
        finally:
            await server.stop()

    async def test_start_creates_pid_file(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            assert pid_path.exists()
            pid = int(pid_path.read_text().strip())
            assert pid > 0
        finally:
            await server.stop()

    async def test_stop_removes_socket_and_pid(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        await server.stop()
        assert not socket_path.exists()
        assert not pid_path.exists()

    async def test_start_removes_stale_socket_file(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.write_text("stale")
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            assert socket_path.exists()
        finally:
            await server.stop()

    def test_is_running_false_when_not_started(self, pid_path: Path) -> None:
        running, pid = DaemonServer.is_running(pid_file=pid_path)
        assert running is False
        assert pid is None

    async def test_is_running_detects_active_daemon(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            running, pid = DaemonServer.is_running(pid_file=pid_path)
            assert running is True
            assert pid is not None
        finally:
            await server.stop()


# ------------------------------------------------------------------
# Evaluation
# ------------------------------------------------------------------


class TestDaemonServerEvaluation:
    """Policy evaluation over the socket."""

    async def test_allowed_tool_returns_allow(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_read")
            )
            assert resp.decision == "allow"
        finally:
            await server.stop()

    async def test_denied_tool_returns_deny(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.decision == "deny"
        finally:
            await server.stop()

    async def test_deny_includes_policy_name(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.policy == "deny-delete"
        finally:
            await server.stop()

    async def test_deny_includes_reason(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.reason is not None
        finally:
            await server.stop()

    async def test_default_deny_for_unmatched_tool(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="unknown_tool")
            )
            assert resp.decision == "deny"
        finally:
            await server.stop()

    async def test_latency_ms_populated(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            resp = await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_read")
            )
            assert resp.latency_ms >= 0.0
        finally:
            await server.stop()

    async def test_agent_id_forwarded_to_guard(
        self, socket_path: Path, pid_path: Path
    ) -> None:
        """Verify the agent field reaches Guard.evaluate as agent_id."""
        captured: list[str | None] = []
        policy = PolicyConfig(
            policies=[PolicyRule(name="allow-all", tools=["*"], action="allow")]
        )
        guard = Guard(policy=policy, self_protection=False)

        # Monkey-patch to capture agent_id
        original = guard.evaluate

        def patched(tool: str, args: dict | None = None, **kwargs):  # type: ignore[override]
            captured.append(kwargs.get("agent_id"))
            return original(tool=tool, args=args, **kwargs)

        guard.evaluate = patched  # type: ignore[assignment]

        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            await _send_request(
                socket_path,
                EvaluateRequest(agent="claude-code", tool="Bash"),
            )
            assert captured == ["claude-code"]
        finally:
            await server.stop()

    async def test_malformed_json_returns_deny(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            raw = await _send_raw(socket_path, b"not valid json\n")
            resp = json.loads(raw)
            assert resp["decision"] == "deny"
            assert "malformed" in resp.get("reason", "").lower()
        finally:
            await server.stop()

    async def test_empty_request_returns_deny(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            raw = await _send_raw(socket_path, b"{}\n")
            resp = json.loads(raw)
            assert resp["decision"] == "deny"
        finally:
            await server.stop()


# ------------------------------------------------------------------
# Concurrency
# ------------------------------------------------------------------


class TestDaemonServerConcurrency:
    """Multiple concurrent and sequential connections."""

    async def test_ten_concurrent_connections(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            tasks = [
                _send_request(socket_path, EvaluateRequest(agent="test", tool="file_read"))
                for _ in range(10)
            ]
            results = await asyncio.gather(*tasks)
            assert all(r.decision == "allow" for r in results)
        finally:
            await server.stop()

    async def test_rapid_sequential_connections(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            for _ in range(20):
                resp = await _send_request(
                    socket_path, EvaluateRequest(agent="test", tool="file_read")
                )
                assert resp.decision == "allow"
        finally:
            await server.stop()


# ------------------------------------------------------------------
# Event bus integration
# ------------------------------------------------------------------


class TestDaemonServerEvents:
    """EventBus integration."""

    async def test_evaluation_emits_to_event_bus(
        self, guard: Guard, socket_path: Path, pid_path: Path
    ) -> None:
        events: list[object] = []
        EventBus.get().subscribe(lambda e: events.append(e))

        server = DaemonServer(guard, socket_path=socket_path, pid_file=pid_path)
        await server.start()
        try:
            await _send_request(
                socket_path, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert len(events) >= 1
        finally:
            await server.stop()
