"""Tests for the MCP HTTP proxy (Streamable HTTP transport)."""

from __future__ import annotations

from typing import Any

import pytest

from avakill.core.engine import Guard
from avakill.core.exceptions import ConfigError
from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
)
from avakill.logging.event_bus import EventBus
from avakill.mcp.proxy import MCPHTTPProxy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_event_bus():
    EventBus.reset()
    yield
    EventBus.reset()


@pytest.fixture()
def allow_policy() -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="deny-delete", tools=["delete_*", "drop_*"], action="deny"),
        ],
    )


@pytest.fixture()
def guard(allow_policy: PolicyConfig) -> Guard:
    return Guard(policy=allow_policy)


# ---------------------------------------------------------------------------
# TestMCPHTTPProxy
# ---------------------------------------------------------------------------


class TestMCPHTTPProxy:
    """Test MCPHTTPProxy initialization and configuration."""

    def test_init_stores_config(self, guard: Guard) -> None:
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        assert proxy.upstream_url == "http://localhost:8080"
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 5100

    def test_init_custom_host_port(self, guard: Guard) -> None:
        proxy = MCPHTTPProxy("http://localhost:8080", guard, host="0.0.0.0", port=9000)
        assert proxy.host == "0.0.0.0"
        assert proxy.port == 9000

    def test_init_no_guard_no_daemon_no_policy_raises(self) -> None:
        with pytest.raises(ConfigError, match="requires guard, daemon_socket, or policy"):
            MCPHTTPProxy("http://localhost:8080")

    def test_init_with_policy(self, tmp_path: Any) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        proxy = MCPHTTPProxy("http://localhost:8080", policy=policy_file)
        assert proxy.guard is not None

    def test_handle_tools_call_allowed(self, guard: Guard) -> None:
        """Allowed tools/call returns None from evaluator (forward)."""
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("read_file", {"path": "/tmp/x"})
        assert decision.allowed is True

    def test_handle_tools_call_denied(self, guard: Guard) -> None:
        """Denied tools/call returns a deny Decision."""
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("delete_file", {"path": "/etc/passwd"})
        assert decision.allowed is False

    def test_deny_response_format_matches_mcp_spec(self, guard: Guard) -> None:
        """The deny Decision contains appropriate info for MCP error response."""
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("drop_table", {})
        assert decision.allowed is False
        assert decision.policy_name is not None

    def test_handle_non_tools_call_decision(self, guard: Guard) -> None:
        """Non-tools/call methods should pass through — the evaluator only runs
        on tools/call, so just verify the evaluator works for allowed tools."""
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("search", {"q": "test"})
        assert decision.allowed is True


class TestMCPHTTPProxyIntegration:
    """Integration tests for the HTTP proxy (require aiohttp)."""

    async def test_start_binds_to_port(self, guard: Guard) -> None:
        """Verify start() initializes the aiohttp server."""
        try:
            import aiohttp  # noqa: F401
        except ImportError:
            pytest.skip("aiohttp not installed")

        proxy = MCPHTTPProxy("http://localhost:9999", guard, port=0)
        await proxy.start()
        assert proxy._runner is not None
        assert proxy._site is not None
        await proxy.stop()

    async def test_stop_releases_port(self, guard: Guard) -> None:
        """Verify stop() cleans up the server."""
        try:
            import aiohttp  # noqa: F401
        except ImportError:
            pytest.skip("aiohttp not installed")

        proxy = MCPHTTPProxy("http://localhost:9999", guard, port=0)
        await proxy.start()
        await proxy.stop()
        assert proxy._runner is None
        assert proxy._site is None
        assert proxy._app is None

    async def test_full_request_cycle(self, guard: Guard) -> None:
        """Start proxy, make a request, stop proxy."""
        try:
            from aiohttp import ClientSession
        except ImportError:
            pytest.skip("aiohttp not installed")

        # Use port 0 for a random available port
        proxy = MCPHTTPProxy("http://httpbin.org", guard, port=0)
        await proxy.start()

        # Get the actual bound port
        assert proxy._site is not None
        sockets = proxy._site._server.sockets
        if sockets:
            port = sockets[0].getsockname()[1]

            # Make a tools/call request that should be denied
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "delete_file", "arguments": {"path": "/etc/passwd"}},
            }
            async with (
                ClientSession() as session,
                session.post(f"http://127.0.0.1:{port}/mcp", json=body) as resp,
            ):
                assert resp.status == 200
                result = await resp.json()
                assert result["result"]["isError"] is True
                assert "AvaKill blocked" in result["result"]["content"][0]["text"]

        await proxy.stop()
