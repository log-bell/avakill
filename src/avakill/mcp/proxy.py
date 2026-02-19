"""MCP proxy module for transparent tool call interception.

Implements a stdio-based transparent proxy that sits between an MCP client
(Claude Desktop, Cursor, etc.) and an upstream MCP server.  All messages pass
through unchanged except ``tools/call``, which is evaluated against the
AvaKill policy before being forwarded.

Supports three evaluation modes:
- **Embedded Guard** — policy evaluated in-process (default).
- **Daemon mode** — evaluation delegated to a running AvaKill daemon.
- **Standalone** — Guard loaded from a policy file (no daemon needed).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from avakill.core.engine import Guard
from avakill.core.exceptions import ConfigError, RateLimitExceeded
from avakill.core.models import Decision

logger = logging.getLogger("avakill.mcp")


class MCPProxyServer:
    """Transparent MCP proxy that intercepts ``tools/call`` requests.

    The proxy spawns the real upstream MCP server as a child process and
    relays JSON-RPC messages over stdio in both directions.  Only
    ``tools/call`` requests are intercepted: they are evaluated against
    the :class:`Guard` policy, and denied calls are short-circuited with
    a well-formed MCP error response so the upstream never sees them.

    Supports three evaluation modes:

    1. **Embedded Guard** (``guard=...``) — direct in-process evaluation.
    2. **Daemon mode** (``daemon_socket=...``) — evaluation via DaemonClient.
    3. **Standalone** (``policy=...``) — Guard loaded from a policy file.

    Deployment — replace the real server command in your MCP client config::

        # Before
        {"mcpServers": {"db": {"command": "python", "args": ["db_server.py"]}}}

        # After
        {"mcpServers": {"db": {
            "command": "avakill",
            "args": ["mcp-proxy", "--upstream-cmd", "python",
                     "--upstream-args", "db_server.py",
                     "--policy", "avakill.yaml"]
        }}}
    """

    def __init__(
        self,
        upstream_cmd: str,
        upstream_args: list[str],
        guard: Guard | None = None,
        *,
        daemon_socket: str | Path | None = None,
        policy: str | Path | None = None,
        agent: str = "mcp",
    ) -> None:
        self.upstream_cmd = upstream_cmd
        self.upstream_args = upstream_args
        self._agent = agent
        self.upstream_process: asyncio.subprocess.Process | None = None
        self._running = False
        self._client_write_lock: asyncio.Lock = asyncio.Lock()
        self._relay_tasks: list[asyncio.Task[None]] = []

        # Select evaluation strategy
        if guard is not None:
            self.guard = guard
            self._evaluator = self._evaluate_guard
        elif daemon_socket is not None:
            self.guard = None  # type: ignore[assignment]
            self._daemon_socket = Path(daemon_socket)
            self._evaluator = self._evaluate_daemon
        elif policy is not None:
            self.guard = Guard(policy=policy)
            self._evaluator = self._evaluate_guard
        else:
            raise ConfigError("MCP proxy requires guard, daemon_socket, or policy")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the proxy: spawn the upstream process and relay stdio."""
        loop = asyncio.get_running_loop()

        if sys.platform == "win32":
            signal.signal(signal.SIGINT, lambda *_: asyncio.ensure_future(self.shutdown()))
        else:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.ensure_future(self.shutdown()))

        self.upstream_process = await asyncio.create_subprocess_exec(
            self.upstream_cmd,
            *self.upstream_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wrap our own stdin/stdout as async streams.
        client_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(client_reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        transport, _ = await loop.connect_write_pipe(
            lambda: asyncio.BaseProtocol(), sys.stdout.buffer
        )
        client_writer = asyncio.StreamWriter(transport, protocol, client_reader, loop)

        stderr_task = asyncio.create_task(self._relay_stderr(self.upstream_process.stderr))

        assert self.upstream_process.stdout is not None
        assert self.upstream_process.stdin is not None
        try:
            await self.run(
                client_reader,
                client_writer,
                self.upstream_process.stdout,
                self.upstream_process.stdin,
            )
        finally:
            stderr_task.cancel()

    async def run(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: Any,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: Any,
    ) -> None:
        """Core relay loop — separated from :meth:`start` for testability.

        Args:
            client_reader: Stream to read client (MCP host) messages from.
            client_writer: Stream to write responses back to the client.
            upstream_reader: Stream to read upstream MCP server messages from.
            upstream_writer: Stream to forward client messages to the upstream.
        """
        self._running = True
        self._client_write_lock = asyncio.Lock()

        self._relay_tasks = [
            asyncio.create_task(
                self._relay_client_to_upstream(client_reader, upstream_writer, client_writer),
                name="client-to-upstream",
            ),
            asyncio.create_task(
                self._relay_upstream_to_client(upstream_reader, client_writer),
                name="upstream-to-client",
            ),
        ]

        try:
            done, pending = await asyncio.wait(
                self._relay_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    logger.error("Relay task '%s' failed: %s", task.get_name(), task.exception())
        finally:
            self._relay_tasks = []
            self._running = False

    async def shutdown(self) -> None:
        """Gracefully shut down the proxy and terminate the upstream process."""
        self._running = False

        # Cancel relay tasks so blocked I/O calls are interrupted.
        for task in self._relay_tasks:
            task.cancel()

        if self.upstream_process is not None:
            try:
                self.upstream_process.terminate()
                await asyncio.wait_for(self.upstream_process.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                with contextlib.suppress(ProcessLookupError):
                    self.upstream_process.kill()
            self.upstream_process = None

        logger.info("AvaKill MCP proxy shut down.")

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    def _evaluate_guard(self, tool: str, args: dict[str, Any]) -> Decision:
        """Evaluate using the embedded or standalone Guard instance."""
        try:
            return self.guard.evaluate(tool=tool, args=args)
        except RateLimitExceeded as exc:
            return exc.decision

    def _evaluate_daemon(self, tool: str, args: dict[str, Any]) -> Decision:
        """Evaluate via DaemonClient over Unix socket."""
        from avakill.daemon.client import DaemonClient
        from avakill.daemon.protocol import EvaluateRequest

        client = DaemonClient(socket_path=self._daemon_socket)
        request = EvaluateRequest(agent=self._agent, tool=tool, args=args)
        try:
            resp = client.evaluate(request)
        except Exception:  # noqa: BLE001
            # Fail-closed: deny on any communication error
            return Decision(
                allowed=False,
                action="deny",
                reason="daemon unavailable",
            )
        allowed = resp.decision == "allow"
        return Decision(
            allowed=allowed,
            action=resp.decision,
            policy_name=resp.policy,
            reason=resp.reason,
        )

    async def _handle_client_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a message from the client before forwarding to upstream.

        For ``tools/call``: evaluate against the Guard policy.  If denied,
        return a synthetic MCP error response; the upstream never sees the
        request.  For every other method, return ``None`` to indicate the
        message should be forwarded verbatim.

        Returns:
            A JSON-RPC response dict when the call is blocked, or ``None``
            to forward the original message to the upstream.
        """
        method = message.get("method")

        if method != "tools/call":
            return None

        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        request_id = message.get("id")

        decision = self._evaluator(tool_name, arguments)

        if decision.allowed:
            return None  # Forward to upstream

        reason = decision.reason or "Denied by policy"
        policy_name = decision.policy_name or "unknown"

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"\u26d4 AvaKill blocked this tool call: "
                            f"{reason}. Policy: {policy_name}"
                        ),
                    }
                ],
                "isError": True,
            },
        }

    async def _handle_upstream_message(
        self,
        message: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Process a message from the upstream before forwarding to the client.

        Currently passes everything through unchanged.

        Returns:
            The message to forward, or ``None`` to drop it.
        """
        return message

    # ------------------------------------------------------------------
    # JSON-RPC I/O
    # ------------------------------------------------------------------

    async def _read_jsonrpc(self, stream: asyncio.StreamReader) -> dict[str, Any] | None:
        """Read a single JSON-RPC message from *stream*.

        Supports two framing formats:

        * **Newline-delimited JSON** — the standard MCP stdio encoding.
        * **Content-Length header framing** — LSP-style, used by some
          MCP implementations.

        Returns:
            A parsed message dict, or ``None`` on EOF.
        """
        while True:
            try:
                line = await stream.readline()
                if not line:
                    return None  # EOF

                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue  # skip blank lines between messages

                if line_str.startswith("Content-Length:"):
                    content_length = int(line_str.split(":", 1)[1].strip())
                    # Consume remaining headers until the blank separator.
                    while True:
                        header_line = await stream.readline()
                        if not header_line or header_line.strip() == b"":
                            break
                    body = await stream.readexactly(content_length)
                    result: dict[str, Any] = json.loads(body.decode("utf-8"))
                    return result

                parsed: dict[str, Any] = json.loads(line_str)
                return parsed

            except (json.JSONDecodeError, asyncio.IncompleteReadError, UnicodeDecodeError) as exc:
                logger.warning("Failed to read JSON-RPC message: %s", exc)
                return None
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("Unexpected error reading JSON-RPC: %s", exc)
                return None

    async def _write_jsonrpc(self, stream: Any, message: dict[str, Any]) -> None:
        """Write a JSON-RPC message as newline-delimited JSON."""
        try:
            data = json.dumps(message, separators=(",", ":")) + "\n"
            stream.write(data.encode("utf-8"))
            await stream.drain()
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            logger.warning("Failed to write JSON-RPC message: %s", exc)

    # ------------------------------------------------------------------
    # Internal relay loops
    # ------------------------------------------------------------------

    async def _relay_client_to_upstream(
        self,
        client_reader: asyncio.StreamReader,
        upstream_writer: Any,
        client_writer: Any,
    ) -> None:
        """Read from the client, evaluate, and either forward or block."""
        while self._running:
            message = await self._read_jsonrpc(client_reader)
            if message is None:
                break

            response = await self._handle_client_message(message)

            if response is not None:
                # Denied — send the canned response directly to the client.
                async with self._client_write_lock:
                    await self._write_jsonrpc(client_writer, response)
            else:
                # Allowed / passthrough — forward to upstream.
                await self._write_jsonrpc(upstream_writer, message)

    async def _relay_upstream_to_client(
        self,
        upstream_reader: asyncio.StreamReader,
        client_writer: Any,
    ) -> None:
        """Read from the upstream and forward responses to the client."""
        while self._running:
            message = await self._read_jsonrpc(upstream_reader)
            if message is None:
                break

            result = await self._handle_upstream_message(message)
            if result is not None:
                async with self._client_write_lock:
                    await self._write_jsonrpc(client_writer, result)

    async def _relay_stderr(self, stderr_stream: asyncio.StreamReader | None) -> None:
        """Forward upstream stderr to the logger."""
        if stderr_stream is None:
            return
        try:
            while True:
                line = await stderr_stream.readline()
                if not line:
                    break
                logger.warning(
                    "upstream stderr: %s",
                    line.decode("utf-8", errors="replace").rstrip(),
                )
        except asyncio.CancelledError:
            pass


class MCPHTTPProxy:
    """HTTP-based MCP proxy for Streamable HTTP transport.

    Listens on a local port and forwards requests to an upstream HTTP MCP
    server, intercepting ``tools/call`` requests and evaluating them against
    the :class:`Guard` policy.

    Planned for v1.1.
    """

    def __init__(
        self,
        upstream_url: str,
        guard: Guard,
        host: str = "127.0.0.1",
        port: int = 5100,
    ) -> None:
        self.upstream_url = upstream_url
        self.guard = guard
        self.host = host
        self.port = port

    async def start(self) -> None:
        """Start the HTTP proxy server."""
        raise NotImplementedError("HTTP transport proxy is planned for v1.1")

    async def stop(self) -> None:
        """Stop the HTTP proxy server."""
        raise NotImplementedError("HTTP transport proxy is planned for v1.1")
