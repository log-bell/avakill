"""Tests for daemon transport abstraction.

TCP tests run on all platforms (including Windows).
Unix transport tests are skipped on Windows.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig
from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_response,
    serialize_request,
)
from avakill.daemon.server import DaemonServer
from avakill.daemon.transport import (
    TCPClientTransport,
    TCPServerTransport,
    UnixClientTransport,
    UnixServerTransport,
    default_client_transport,
    default_server_transport,
)
from avakill.logging.event_bus import EventBus


@pytest.fixture(autouse=True)
def _reset_event_bus() -> None:
    EventBus.reset()
    yield  # type: ignore[misc]
    EventBus.reset()


@pytest.fixture
def guard(sample_policy: PolicyConfig) -> Guard:
    return Guard(policy=sample_policy, self_protection=False)


# ------------------------------------------------------------------
# Factory functions
# ------------------------------------------------------------------


class TestFactoryFunctions:
    """Factory functions return the correct transport for each platform."""

    def test_default_server_transport_unix(self) -> None:
        if sys.platform == "win32":
            pytest.skip("Unix transport not available on Windows")
        transport = default_server_transport()
        assert isinstance(transport, UnixServerTransport)

    def test_default_server_transport_tcp_on_explicit_port(self) -> None:
        transport = default_server_transport(tcp_port=0)
        assert isinstance(transport, TCPServerTransport)

    def test_default_client_transport_unix(self) -> None:
        if sys.platform == "win32":
            pytest.skip("Unix transport not available on Windows")
        transport = default_client_transport()
        assert isinstance(transport, UnixClientTransport)

    def test_default_client_transport_tcp_on_explicit_port(self) -> None:
        transport = default_client_transport(tcp_port=0)
        assert isinstance(transport, TCPClientTransport)


# ------------------------------------------------------------------
# TCP transport (runs on all platforms)
# ------------------------------------------------------------------


@pytest.fixture
def tcp_port_file(tmp_path: Path) -> Path:
    return tmp_path / "avakill.port"


@pytest.fixture
def pid_path(tmp_path: Path) -> Path:
    return tmp_path / "avakill.pid"


async def _send_tcp_request(port: int, req: EvaluateRequest) -> EvaluateResponse:
    """Connect to the daemon via TCP, send one request, return the response."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(serialize_request(req))
    await writer.drain()
    writer.write_eof()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return deserialize_response(raw)


async def _send_tcp_raw(port: int, data: bytes) -> bytes:
    """Send raw bytes via TCP and return the raw response line."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    writer.write_eof()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return raw


class TestTCPServerTransport:
    """TCP server transport lifecycle."""

    async def test_start_writes_port_file(self, tcp_port_file: Path) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        handler_called = False

        async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            nonlocal handler_called
            handler_called = True

        server = await transport.start(handler)
        try:
            assert tcp_port_file.exists()
            port = int(tcp_port_file.read_text().strip())
            assert port > 0
            assert transport.port == port
        finally:
            server.close()
            await server.wait_closed()
            await transport.cleanup()

    async def test_cleanup_removes_port_file(self, tcp_port_file: Path) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)

        async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            pass

        server = await transport.start(handler)
        server.close()
        await server.wait_closed()
        await transport.cleanup()
        assert not tcp_port_file.exists()

    def test_display_address(self) -> None:
        transport = TCPServerTransport(port=19426)
        assert "127.0.0.1:19426" in transport.display_address()


class TestTCPClientTransport:
    """TCP client transport connection."""

    def test_connect_refused_raises(self) -> None:
        transport = TCPClientTransport(port=19999)
        with pytest.raises(ConnectionRefusedError):
            transport.connect(timeout=0.5)

    def test_missing_port_file_raises(self, tmp_path: Path) -> None:
        transport = TCPClientTransport(port_file=tmp_path / "nonexistent.port")
        with pytest.raises(ConnectionError, match="port file not found"):
            transport.connect(timeout=0.5)

    def test_invalid_port_file_raises(self, tmp_path: Path) -> None:
        port_file = tmp_path / "bad.port"
        port_file.write_text("not_a_number")
        transport = TCPClientTransport(port_file=port_file)
        with pytest.raises(ConnectionError, match="Cannot read daemon port file"):
            transport.connect(timeout=0.5)


# ------------------------------------------------------------------
# DaemonServer over TCP (runs on all platforms)
# ------------------------------------------------------------------


class TestDaemonServerTCP:
    """DaemonServer using TCP transport — runs on all platforms."""

    async def test_start_and_stop(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            assert pid_path.exists()
            assert tcp_port_file.exists()
        finally:
            await server.stop()
        assert not pid_path.exists()
        assert not tcp_port_file.exists()

    async def test_allowed_tool(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            resp = await _send_tcp_request(
                port, EvaluateRequest(agent="test", tool="file_read")
            )
            assert resp.decision == "allow"
        finally:
            await server.stop()

    async def test_denied_tool(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            resp = await _send_tcp_request(
                port, EvaluateRequest(agent="test", tool="file_delete")
            )
            assert resp.decision == "deny"
            assert resp.policy == "deny-delete"
        finally:
            await server.stop()

    async def test_malformed_json(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            raw = await _send_tcp_raw(port, b"not valid json\n")
            resp = json.loads(raw)
            assert resp["decision"] == "deny"
            assert "malformed" in resp.get("reason", "").lower()
        finally:
            await server.stop()

    async def test_concurrent_tcp_connections(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            tasks = [
                _send_tcp_request(
                    port, EvaluateRequest(agent="test", tool="file_read")
                )
                for _ in range(10)
            ]
            results = await asyncio.gather(*tasks)
            assert all(r.decision == "allow" for r in results)
        finally:
            await server.stop()


# ------------------------------------------------------------------
# DaemonClient over TCP (runs on all platforms)
# ------------------------------------------------------------------


class TestDaemonClientTCP:
    """DaemonClient using TCP transport — runs on all platforms."""

    async def test_evaluate_via_tcp(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        from avakill.daemon.client import DaemonClient

        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            client = DaemonClient(tcp_port=port)
            resp = await asyncio.to_thread(
                client.evaluate, EvaluateRequest(agent="test", tool="file_read")
            )
            assert resp.decision == "allow"
        finally:
            await server.stop()

    async def test_ping_via_tcp(
        self, guard: Guard, pid_path: Path, tcp_port_file: Path
    ) -> None:
        from avakill.daemon.client import DaemonClient

        transport = TCPServerTransport(port=0, port_file=tcp_port_file)
        server = DaemonServer(
            guard, pid_file=pid_path, transport=transport
        )
        await server.start()
        try:
            port = transport.port
            assert port is not None
            client = DaemonClient(tcp_port=port)
            result = await asyncio.to_thread(client.ping)
            assert result is True
        finally:
            await server.stop()

    def test_tcp_connection_refused_returns_deny(self) -> None:
        from avakill.daemon.client import DaemonClient

        client = DaemonClient(tcp_port=19999, timeout=0.5)
        resp = client.evaluate(EvaluateRequest(agent="test", tool="file_read"))
        assert resp.decision == "deny"
        assert "daemon unavailable" in (resp.reason or "")

    def test_tcp_ping_no_daemon(self) -> None:
        from avakill.daemon.client import DaemonClient

        client = DaemonClient(tcp_port=19999, timeout=0.5)
        assert client.ping() is False
