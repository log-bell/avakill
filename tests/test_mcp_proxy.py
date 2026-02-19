"""Tests for the MCP transparent proxy (stdio transport)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from avakill.core.engine import Guard
from avakill.core.exceptions import ConfigError
from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    RateLimit,
    RuleConditions,
)
from avakill.logging.event_bus import EventBus
from avakill.mcp.proxy import MCPHTTPProxy, MCPProxyServer

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _jsonrpc_request(method: str, params: dict | None = None, *, id: int = 1) -> dict:
    """Build a JSON-RPC 2.0 request message."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        msg["params"] = params
    return msg


def _jsonrpc_notification(method: str, params: dict | None = None) -> dict:
    """Build a JSON-RPC 2.0 notification (no ``id``)."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _jsonrpc_response(id: int, result: Any) -> dict:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _encode(msg: dict) -> bytes:
    """Encode a message as newline-delimited JSON bytes."""
    return (json.dumps(msg) + "\n").encode()


class MockStreamWriter:
    """Collects bytes written via write() / drain() for later inspection."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        pass

    def get_messages(self) -> list[dict]:
        """Parse all accumulated newline-delimited JSON messages."""
        messages = []
        for line in self._buffer.decode("utf-8").split("\n"):
            line = line.strip()
            if line:
                messages.append(json.loads(line))
        return messages

    def clear(self) -> None:
        self._buffer.clear()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_event_bus():
    """Ensure each test gets a fresh EventBus singleton."""
    EventBus.reset()
    yield
    EventBus.reset()


@pytest.fixture()
def allow_policy() -> PolicyConfig:
    """Allows most tools by default, denies destructive ones explicitly."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="deny-delete", tools=["delete_*", "drop_*"], action="deny"),
            PolicyRule(
                name="deny-destructive-sql",
                tools=["database_query", "sql_*"],
                action="deny",
                conditions=RuleConditions(
                    args_match={"query": ["DROP", "DELETE", "TRUNCATE", "ALTER"]},
                ),
            ),
        ],
    )


@pytest.fixture()
def deny_policy() -> PolicyConfig:
    """Denies by default, allows only specific tools."""
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-read", tools=["read_*", "search"], action="allow"),
        ],
    )


@pytest.fixture()
def rate_limit_policy() -> PolicyConfig:
    """Allows a tool but with a tight rate limit."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(
                name="rate-limited",
                tools=["search"],
                action="allow",
                rate_limit=RateLimit(max_calls=2, window="60s"),
            ),
        ],
    )


@pytest.fixture()
def guard(allow_policy: PolicyConfig) -> Guard:
    return Guard(policy=allow_policy)


@pytest.fixture()
def deny_guard(deny_policy: PolicyConfig) -> Guard:
    return Guard(policy=deny_policy)


@pytest.fixture()
def rate_guard(rate_limit_policy: PolicyConfig) -> Guard:
    return Guard(policy=rate_limit_policy)


@pytest.fixture()
def proxy(guard: Guard) -> MCPProxyServer:
    return MCPProxyServer(upstream_cmd="echo", upstream_args=[], guard=guard)


@pytest.fixture()
def deny_proxy(deny_guard: Guard) -> MCPProxyServer:
    return MCPProxyServer(upstream_cmd="echo", upstream_args=[], guard=deny_guard)


# ---------------------------------------------------------------------------
# _handle_client_message — unit tests
# ---------------------------------------------------------------------------


class TestHandleClientMessage:
    """Verify tools/call interception and passthrough for other methods."""

    async def test_initialize_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("initialize", {"capabilities": {}})
        assert await proxy._handle_client_message(msg) is None

    async def test_ping_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("ping")
        assert await proxy._handle_client_message(msg) is None

    async def test_notifications_pass_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_notification("notifications/initialized")
        assert await proxy._handle_client_message(msg) is None

    async def test_tools_list_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("tools/list")
        assert await proxy._handle_client_message(msg) is None

    async def test_resources_list_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("resources/list")
        assert await proxy._handle_client_message(msg) is None

    async def test_prompts_list_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("prompts/list")
        assert await proxy._handle_client_message(msg) is None

    async def test_tools_call_allowed(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "read_file", "arguments": {"path": "/tmp/notes.txt"}},
        )
        assert await proxy._handle_client_message(msg) is None

    async def test_tools_call_denied(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "delete_file", "arguments": {"path": "/etc/passwd"}},
            id=42,
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 42
        assert result["result"]["isError"] is True

    async def test_denied_response_preserves_request_id(self, proxy: MCPProxyServer) -> None:
        for req_id in (1, 99, 12345):
            msg = _jsonrpc_request(
                "tools/call",
                {"name": "delete_file", "arguments": {}},
                id=req_id,
            )
            result = await proxy._handle_client_message(msg)
            assert result is not None
            assert result["id"] == req_id

    async def test_denied_response_contains_reason(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {}})
        result = await proxy._handle_client_message(msg)
        assert result is not None
        text = result["result"]["content"][0]["text"]
        assert "AvaKill blocked" in text

    async def test_denied_response_contains_policy_name(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {}})
        result = await proxy._handle_client_message(msg)
        assert result is not None
        text = result["result"]["content"][0]["text"]
        assert "deny-delete" in text

    async def test_denied_response_mcp_format(self, proxy: MCPProxyServer) -> None:
        """The blocked response must conform to the MCP tool result schema."""
        msg = _jsonrpc_request("tools/call", {"name": "drop_table", "arguments": {}})
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert "result" in result
        content = result["result"]["content"]
        assert isinstance(content, list)
        assert len(content) == 1
        assert content[0]["type"] == "text"
        assert result["result"]["isError"] is True

    async def test_default_deny_blocks_unknown_tool(self, deny_proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("tools/call", {"name": "unknown_tool", "arguments": {}})
        result = await deny_proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True

    async def test_default_deny_allows_permitted_tool(self, deny_proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request("tools/call", {"name": "read_config", "arguments": {}})
        assert await deny_proxy._handle_client_message(msg) is None

    async def test_tools_call_missing_params_treated_as_empty(self, proxy: MCPProxyServer) -> None:
        msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
        # With default_action=allow and no matching deny rule for empty tool name,
        # the call should pass through.
        result = await proxy._handle_client_message(msg)
        assert result is None


class TestHandleClientMessageSQL:
    """Test argument-based conditions (destructive SQL detection)."""

    async def test_select_query_allowed(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "database_query", "arguments": {"query": "SELECT * FROM users"}},
        )
        assert await proxy._handle_client_message(msg) is None

    async def test_drop_table_denied(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "database_query", "arguments": {"query": "DROP TABLE users"}},
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True
        assert "deny-destructive-sql" in result["result"]["content"][0]["text"]

    async def test_delete_from_denied(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "database_query", "arguments": {"query": "DELETE FROM users WHERE 1=1"}},
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True

    async def test_truncate_denied(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "sql_exec", "arguments": {"query": "TRUNCATE TABLE sessions"}},
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True

    async def test_alter_table_denied(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_request(
            "tools/call",
            {"name": "sql_exec", "arguments": {"query": "ALTER TABLE users ADD COLUMN x"}},
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True


class TestHandleClientMessageRateLimit:
    """Verify rate-limited tools/call requests are blocked after quota."""

    async def test_rate_limit_blocks_after_quota(self, rate_guard: Guard) -> None:
        proxy = MCPProxyServer("echo", [], rate_guard)
        msg = _jsonrpc_request("tools/call", {"name": "search", "arguments": {"q": "a"}})

        # First two calls allowed (max_calls=2)
        assert await proxy._handle_client_message(msg) is None
        assert await proxy._handle_client_message(msg) is None

        # Third call blocked
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True
        assert "Rate limit" in result["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# _handle_upstream_message — unit tests
# ---------------------------------------------------------------------------


class TestHandleUpstreamMessage:
    """Upstream messages are passed through unchanged."""

    async def test_result_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_response(1, {"capabilities": {}})
        assert await proxy._handle_upstream_message(msg) == msg

    async def test_tools_list_result_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_response(
            2,
            {"tools": [{"name": "read_file"}, {"name": "delete_file"}]},
        )
        assert await proxy._handle_upstream_message(msg) == msg

    async def test_error_response_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32600, "message": "Invalid"}}
        assert await proxy._handle_upstream_message(msg) == msg

    async def test_notification_passes_through(self, proxy: MCPProxyServer) -> None:
        msg = _jsonrpc_notification("notifications/progress", {"token": "abc", "value": 50})
        assert await proxy._handle_upstream_message(msg) == msg


# ---------------------------------------------------------------------------
# _read_jsonrpc / _write_jsonrpc — unit tests
# ---------------------------------------------------------------------------


class TestReadJsonRPC:
    """Verify newline-delimited and Content-Length framing."""

    async def test_newline_delimited(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        msg = {"jsonrpc": "2.0", "method": "ping", "id": 1}
        reader.feed_data(_encode(msg))
        reader.feed_eof()
        assert await proxy._read_jsonrpc(reader) == msg

    async def test_content_length_framing(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1})
        frame = f"Content-Length: {len(body)}\r\n\r\n{body}".encode()
        reader.feed_data(frame)
        reader.feed_eof()
        result = await proxy._read_jsonrpc(reader)
        assert result is not None
        assert result["method"] == "ping"

    async def test_content_length_with_extra_headers(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1})
        frame = (
            f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n{body}"
        ).encode()
        reader.feed_data(frame)
        reader.feed_eof()
        result = await proxy._read_jsonrpc(reader)
        assert result is not None
        assert result["method"] == "ping"

    async def test_eof_returns_none(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        reader.feed_eof()
        assert await proxy._read_jsonrpc(reader) is None

    async def test_blank_lines_are_skipped(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        msg = {"jsonrpc": "2.0", "method": "ping", "id": 1}
        # Blank lines before the actual message.
        reader.feed_data(b"\n\n")
        reader.feed_data(_encode(msg))
        reader.feed_eof()
        assert await proxy._read_jsonrpc(reader) == msg

    async def test_invalid_json_returns_none(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"NOT JSON\n")
        reader.feed_eof()
        assert await proxy._read_jsonrpc(reader) is None

    async def test_multiple_messages(self, proxy: MCPProxyServer) -> None:
        reader = asyncio.StreamReader()
        msg1 = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        msg2 = {"jsonrpc": "2.0", "method": "ping", "id": 2}
        reader.feed_data(_encode(msg1) + _encode(msg2))
        reader.feed_eof()
        assert await proxy._read_jsonrpc(reader) == msg1
        assert await proxy._read_jsonrpc(reader) == msg2


class TestWriteJsonRPC:
    """Verify newline-delimited JSON output."""

    async def test_writes_valid_json(self, proxy: MCPProxyServer) -> None:
        writer = MockStreamWriter()
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        await proxy._write_jsonrpc(writer, msg)
        messages = writer.get_messages()
        assert len(messages) == 1
        assert messages[0] == msg

    async def test_output_ends_with_newline(self, proxy: MCPProxyServer) -> None:
        writer = MockStreamWriter()
        await proxy._write_jsonrpc(writer, {"jsonrpc": "2.0", "id": 1, "result": {}})
        raw = writer._buffer.decode("utf-8")
        assert raw.endswith("\n")

    async def test_compact_encoding(self, proxy: MCPProxyServer) -> None:
        writer = MockStreamWriter()
        await proxy._write_jsonrpc(writer, {"a": 1, "b": 2})
        raw = writer._buffer.decode("utf-8").strip()
        # Compact separators: no spaces after , or :
        assert " " not in raw


# ---------------------------------------------------------------------------
# Integration tests — full relay loop via run()
# ---------------------------------------------------------------------------


class TestProxyIntegration:
    """End-to-end tests driving the proxy through its run() method."""

    async def test_passthrough_forwarded_to_upstream(self, guard: Guard) -> None:
        """Non-tool messages are forwarded to the upstream writer."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        msg = _jsonrpc_request("initialize", {"capabilities": {}})
        client_reader.feed_data(_encode(msg))
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        forwarded = upstream_writer.get_messages()
        assert len(forwarded) == 1
        assert forwarded[0]["method"] == "initialize"

    async def test_upstream_response_forwarded_to_client(self, guard: Guard) -> None:
        """Responses from the upstream arrive at the client writer."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        # Upstream sends a response.
        response = _jsonrpc_response(1, {"capabilities": {}})
        upstream_reader.feed_data(_encode(response))
        upstream_reader.feed_eof()
        client_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        messages = client_writer.get_messages()
        assert len(messages) == 1
        assert messages[0]["result"]["capabilities"] == {}

    async def test_tools_list_round_trip(self, guard: Guard) -> None:
        """tools/list request flows to upstream and the response comes back."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        # Client sends tools/list
        request = _jsonrpc_request("tools/list", {}, id=1)
        client_reader.feed_data(_encode(request))

        # Upstream replies
        response = _jsonrpc_response(1, {"tools": [{"name": "read_file"}]})
        upstream_reader.feed_data(_encode(response))

        # Close both sides after messages
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        # Request forwarded to upstream
        assert len(upstream_writer.get_messages()) == 1
        # Response forwarded to client
        client_msgs = client_writer.get_messages()
        assert len(client_msgs) == 1
        assert client_msgs[0]["result"]["tools"][0]["name"] == "read_file"

    async def test_allowed_tools_call_forwarded(self, guard: Guard) -> None:
        """An allowed tools/call is forwarded to the upstream."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        msg = _jsonrpc_request(
            "tools/call",
            {"name": "read_file", "arguments": {"path": "/tmp/x"}},
            id=5,
        )
        client_reader.feed_data(_encode(msg))
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        forwarded = upstream_writer.get_messages()
        assert len(forwarded) == 1
        assert forwarded[0]["params"]["name"] == "read_file"

    async def test_denied_tools_call_not_forwarded(self, guard: Guard) -> None:
        """A denied tools/call is NOT forwarded — the upstream sees nothing."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        msg = _jsonrpc_request(
            "tools/call",
            {"name": "delete_file", "arguments": {"path": "/etc/passwd"}},
            id=7,
        )
        client_reader.feed_data(_encode(msg))
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        # Nothing forwarded to upstream
        assert upstream_writer.get_messages() == []

        # Client receives the blocked response
        client_msgs = client_writer.get_messages()
        assert len(client_msgs) == 1
        assert client_msgs[0]["id"] == 7
        assert client_msgs[0]["result"]["isError"] is True
        assert "AvaKill blocked" in client_msgs[0]["result"]["content"][0]["text"]

    async def test_upstream_eof_shuts_down_proxy(self, guard: Guard) -> None:
        """When the upstream closes, the proxy shuts down cleanly."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        # Upstream closes immediately.
        upstream_reader.feed_eof()
        # Client has pending data but the proxy should still shut down.
        client_reader.feed_eof()

        # Should complete without hanging.
        await asyncio.wait_for(
            proxy.run(client_reader, client_writer, upstream_reader, upstream_writer),
            timeout=2.0,
        )
        assert proxy._running is False

    async def test_client_eof_shuts_down_proxy(self, guard: Guard) -> None:
        """When the client closes stdin, the proxy shuts down cleanly."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await asyncio.wait_for(
            proxy.run(client_reader, client_writer, upstream_reader, upstream_writer),
            timeout=2.0,
        )
        assert proxy._running is False

    async def test_mixed_allowed_and_denied(self, guard: Guard) -> None:
        """A batch of messages where some tools/call are allowed and some denied."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        # Allowed
        msg1 = _jsonrpc_request("tools/call", {"name": "read_file", "arguments": {}}, id=1)
        # Denied
        msg2 = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {}}, id=2)
        # Passthrough
        msg3 = _jsonrpc_request("ping", id=3)
        # Allowed
        msg4 = _jsonrpc_request("tools/call", {"name": "search", "arguments": {}}, id=4)

        for msg in (msg1, msg2, msg3, msg4):
            client_reader.feed_data(_encode(msg))
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        # Upstream should have received msg1, msg3, msg4 (allowed/passthrough)
        forwarded = upstream_writer.get_messages()
        forwarded_ids = [m["id"] for m in forwarded]
        assert forwarded_ids == [1, 3, 4]

        # Client should have received the denied response for msg2
        client_msgs = client_writer.get_messages()
        assert len(client_msgs) == 1
        assert client_msgs[0]["id"] == 2
        assert client_msgs[0]["result"]["isError"] is True

    async def test_concurrent_tools_calls(self, guard: Guard) -> None:
        """Multiple rapid tools/call messages are all evaluated correctly."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        # Send 10 allowed and 10 denied calls interleaved.
        for i in range(20):
            if i % 2 == 0:
                msg = _jsonrpc_request("tools/call", {"name": "read_file", "arguments": {}}, id=i)
            else:
                msg = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {}}, id=i)
            client_reader.feed_data(_encode(msg))
        client_reader.feed_eof()
        upstream_reader.feed_eof()

        await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

        forwarded = upstream_writer.get_messages()
        denied = client_writer.get_messages()

        # 10 allowed calls forwarded (even IDs: 0,2,4,...,18)
        assert len(forwarded) == 10
        assert all(m["id"] % 2 == 0 for m in forwarded)

        # 10 denied calls returned to client (odd IDs: 1,3,5,...,19)
        assert len(denied) == 10
        assert all(m["id"] % 2 == 1 for m in denied)
        assert all(m["result"]["isError"] is True for m in denied)


# ---------------------------------------------------------------------------
# Audit trail integration
# ---------------------------------------------------------------------------


class TestAuditIntegration:
    """Every intercepted tools/call is recorded on the event bus."""

    async def test_allowed_call_emits_event(self, guard: Guard) -> None:
        from avakill.core.models import AuditEvent

        received: list[AuditEvent] = []
        bus = EventBus.get()
        unsub = bus.subscribe(received.append)

        proxy = MCPProxyServer("echo", [], guard)
        msg = _jsonrpc_request("tools/call", {"name": "read_file", "arguments": {"path": "/tmp"}})
        await proxy._handle_client_message(msg)

        assert len(received) == 1
        assert received[0].tool_call.tool_name == "read_file"
        assert received[0].decision.allowed is True
        unsub()

    async def test_denied_call_emits_event(self, guard: Guard) -> None:
        from avakill.core.models import AuditEvent

        received: list[AuditEvent] = []
        bus = EventBus.get()
        unsub = bus.subscribe(received.append)

        proxy = MCPProxyServer("echo", [], guard)
        msg = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {"path": "/"}})
        await proxy._handle_client_message(msg)

        assert len(received) == 1
        assert received[0].tool_call.tool_name == "delete_file"
        assert received[0].decision.allowed is False
        unsub()


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------


class TestShutdown:
    """Verify graceful shutdown behaviour."""

    async def test_shutdown_sets_running_false(self, proxy: MCPProxyServer) -> None:
        proxy._running = True
        await proxy.shutdown()
        assert proxy._running is False

    async def test_shutdown_without_upstream_is_safe(self, proxy: MCPProxyServer) -> None:
        proxy.upstream_process = None
        await proxy.shutdown()  # Should not raise

    async def test_shutdown_during_run(self, guard: Guard) -> None:
        """Calling shutdown() while run() is active terminates cleanly."""
        client_reader = asyncio.StreamReader()
        client_writer = MockStreamWriter()
        upstream_reader = asyncio.StreamReader()
        upstream_writer = MockStreamWriter()

        proxy = MCPProxyServer("echo", [], guard)

        async def _shutdown_soon() -> None:
            await asyncio.sleep(0.05)
            await proxy.shutdown()

        shutdown_task = asyncio.create_task(_shutdown_soon())

        # Don't feed EOF — the proxy would hang without the shutdown.
        await asyncio.wait_for(
            proxy.run(client_reader, client_writer, upstream_reader, upstream_writer),
            timeout=2.0,
        )
        await shutdown_task
        assert proxy._running is False


# ---------------------------------------------------------------------------
# Daemon mode — unit tests
# ---------------------------------------------------------------------------


class TestMCPProxyDaemonMode:
    """Verify daemon-mode evaluation via DaemonClient."""

    def test_daemon_mode_sends_to_client(self, tmp_path: Any) -> None:
        """Daemon mode creates a proxy with daemon_socket set."""
        socket_path = tmp_path / "test.sock"
        proxy = MCPProxyServer("echo", [], daemon_socket=socket_path)
        assert proxy._daemon_socket == socket_path
        assert proxy.guard is None

    async def test_daemon_mode_deny_returns_error_response(self, tmp_path: Any) -> None:
        """When daemon is unreachable, evaluation fails closed (deny)."""
        socket_path = tmp_path / "nonexistent.sock"
        proxy = MCPProxyServer("echo", [], daemon_socket=socket_path)

        msg = _jsonrpc_request(
            "tools/call",
            {"name": "delete_file", "arguments": {"path": "/etc/passwd"}},
            id=42,
        )
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["id"] == 42
        assert result["result"]["isError"] is True
        assert "daemon unavailable" in result["result"]["content"][0]["text"]

    async def test_daemon_mode_fallback_on_connection_error(self, tmp_path: Any) -> None:
        """Connection errors fail closed — deny the call."""
        socket_path = tmp_path / "bad.sock"
        proxy = MCPProxyServer("echo", [], daemon_socket=socket_path)

        decision = proxy._evaluate_daemon("read_file", {"path": "/tmp/x"})
        assert decision.allowed is False
        assert "daemon unavailable" in (decision.reason or "")


class TestMCPProxyStandaloneMode:
    """Verify standalone mode (policy file → embedded Guard)."""

    def test_standalone_mode_loads_policy(self, tmp_path: Any) -> None:
        """Standalone mode creates a Guard from the policy file."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        proxy = MCPProxyServer("echo", [], policy=policy_file)
        assert proxy.guard is not None

    async def test_standalone_mode_evaluates_correctly(self, tmp_path: Any) -> None:
        """Standalone mode evaluates tool calls against the loaded policy."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\npolicies:\n"
            "  - name: allow-read\n    tools: ['read_*']\n    action: allow\n"
        )
        proxy = MCPProxyServer("echo", [], policy=policy_file)

        # Allowed
        msg = _jsonrpc_request("tools/call", {"name": "read_file", "arguments": {}})
        assert await proxy._handle_client_message(msg) is None

        # Denied
        msg = _jsonrpc_request("tools/call", {"name": "delete_file", "arguments": {}}, id=5)
        result = await proxy._handle_client_message(msg)
        assert result is not None
        assert result["result"]["isError"] is True


class TestMCPProxyInitValidation:
    """Verify that MCPProxyServer requires at least one evaluation mode."""

    def test_no_guard_no_daemon_no_policy_raises(self) -> None:
        with pytest.raises(ConfigError, match="requires guard, daemon_socket, or policy"):
            MCPProxyServer("echo", [])


# ---------------------------------------------------------------------------
# Tool normalization
# ---------------------------------------------------------------------------


class TestMCPProxyNormalization:
    """Verify tool name normalization before evaluation."""

    async def test_tool_name_normalized_before_evaluation(self) -> None:
        """When agent is 'claude-code', tool name 'Bash' → 'shell_execute'."""
        # Policy that denies shell_execute (canonical name)
        policy = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="deny-shell", tools=["shell_execute"], action="deny"),
            ],
        )
        guard = Guard(policy=policy)
        proxy = MCPProxyServer("echo", [], guard=guard, agent="claude-code")

        # Send a tools/call with agent-native name "Bash"
        msg = _jsonrpc_request("tools/call", {"name": "Bash", "arguments": {"command": "ls"}})
        result = await proxy._handle_client_message(msg)
        # Should be denied because "Bash" normalizes to "shell_execute"
        assert result is not None
        assert result["result"]["isError"] is True

    async def test_no_normalization_when_agent_not_set(self, guard: Guard) -> None:
        """Default agent='mcp' means no normalization."""
        proxy = MCPProxyServer("echo", [], guard=guard)
        assert proxy._normalizer is None

        # "Bash" won't match any deny rule because it's not normalized
        msg = _jsonrpc_request("tools/call", {"name": "Bash", "arguments": {}})
        result = await proxy._handle_client_message(msg)
        assert result is None  # Passes through

    async def test_unknown_tool_passes_through(self) -> None:
        """Unknown tools pass through normalization unchanged."""
        policy = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[],
        )
        guard = Guard(policy=policy)
        proxy = MCPProxyServer("echo", [], guard=guard, agent="claude-code")

        msg = _jsonrpc_request("tools/call", {"name": "CustomTool", "arguments": {}})
        result = await proxy._handle_client_message(msg)
        assert result is None  # Passes through (allowed by default)


# ---------------------------------------------------------------------------
# MCPHTTPProxy — basic tests (full tests in test_mcp_http_proxy.py)
# ---------------------------------------------------------------------------


class TestMCPHTTPProxy:
    """Basic MCPHTTPProxy tests — see test_mcp_http_proxy.py for full coverage."""

    def test_instantiation(self, guard: Guard) -> None:
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        assert proxy.upstream_url == "http://localhost:8080"
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 5100

    def test_evaluator_allows(self, guard: Guard) -> None:
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("read_file", {"path": "/tmp/x"})
        assert decision.allowed is True

    def test_evaluator_denies(self, guard: Guard) -> None:
        proxy = MCPHTTPProxy("http://localhost:8080", guard)
        decision = proxy._evaluator("delete_file", {"path": "/"})
        assert decision.allowed is False
