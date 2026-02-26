"""Integration tests for the dashboard server."""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import pytest


class TestDashboardIntegration:
    """End-to-end tests for the dashboard WebSocket server."""

    async def test_server_starts_and_serves_snapshot(self) -> None:
        """Start server, connect WebSocket, receive snapshot."""
        try:
            from aiohttp import ClientSession, WSMsgType
        except ImportError:
            pytest.skip("aiohttp not installed")

        from avakill.cli.dashboard_cmd import _serve

        root = Path(__file__).resolve().parent.parent
        port = 17700

        server_task = asyncio.create_task(_serve(root, port, no_open=True))
        await asyncio.sleep(0.5)

        try:
            async with (
                ClientSession() as session,
                session.ws_connect(f"http://localhost:{port}/ws") as ws,
            ):
                msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
                assert msg.type == WSMsgType.TEXT
                data = json.loads(msg.data)
                assert "timestamp" in data
                assert "git" in data
                assert "modules" in data
                assert "health" in data
                assert data["project"]["name"] == "avakill"
        finally:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task

    async def test_rerun_check_returns_updated_snapshot(self) -> None:
        """Send a re-run command and verify response."""
        try:
            from aiohttp import ClientSession  # noqa: F811
        except ImportError:
            pytest.skip("aiohttp not installed")

        from avakill.cli.dashboard_cmd import _serve

        root = Path(__file__).resolve().parent.parent
        port = 17701

        server_task = asyncio.create_task(_serve(root, port, no_open=True))
        await asyncio.sleep(0.5)

        try:
            async with (
                ClientSession() as session,
                session.ws_connect(f"http://localhost:{port}/ws") as ws,
            ):
                # Consume initial snapshot
                await asyncio.wait_for(ws.receive(), timeout=5.0)

                # Send re-run command
                await ws.send_str(json.dumps({"action": "run_check", "check": "lint"}))

                # Should get a "running" snapshot
                msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
                data = json.loads(msg.data)
                assert data["health"]["lint"]["status"] == "running"

                # Then a completed snapshot
                msg = await asyncio.wait_for(ws.receive(), timeout=30.0)
                data = json.loads(msg.data)
                assert data["health"]["lint"]["status"] in ("pass", "fail")
        finally:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task
