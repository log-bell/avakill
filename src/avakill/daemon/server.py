"""Persistent AvaKill daemon over Unix domain socket or TCP localhost.

The daemon wraps an existing :class:`Guard` instance and evaluates
incoming :class:`EvaluateRequest` messages, returning an
:class:`EvaluateResponse` for each.  Each client connection is a single
request/response pair (short-lived), matching the lifecycle of an agent
hook script.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from avakill.core.engine import Guard
from avakill.core.exceptions import RateLimitExceeded
from avakill.core.normalization import ToolNormalizer
from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_request,
    serialize_response,
)

if TYPE_CHECKING:
    from avakill.daemon.transport import ServerTransport

logger = logging.getLogger("avakill.daemon")

_CONNECTION_TIMEOUT = 5.0  # seconds
_MAX_REQUEST_SIZE = 64 * 1024  # 64 KiB
_DEFAULT_MAX_CONNECTIONS = 100


class DaemonServer:
    """Asyncio server wrapping :class:`Guard`.

    Supports both Unix domain sockets (Linux/macOS) and TCP localhost
    (Windows) via the transport abstraction.

    Usage::

        guard = Guard(policy="avakill.yaml")
        server = DaemonServer(guard)
        asyncio.run(server.serve_forever())
    """

    def __init__(
        self,
        guard: Guard,
        socket_path: str | Path | None = None,
        pid_file: str | Path | None = None,
        normalizer: ToolNormalizer | None = None,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
        transport: ServerTransport | None = None,
        tcp_port: int | None = None,
    ) -> None:
        self._guard = guard
        self._socket_path = Path(socket_path) if socket_path else self.default_socket_path()
        self._pid_path = Path(pid_file) if pid_file else self.default_pid_path()
        self._normalizer = normalizer or ToolNormalizer()
        self._max_connections = max_connections
        self._conn_semaphore: asyncio.Semaphore | None = None
        self._server: asyncio.AbstractServer | None = None
        self._stop_event: asyncio.Event | None = None

        if transport is not None:
            self._transport = transport
        else:
            from avakill.daemon.transport import (
                TCPServerTransport,
                UnixServerTransport,
                default_server_transport,
            )

            if socket_path is not None:
                self._transport = UnixServerTransport(self._socket_path)
            elif tcp_port is not None:
                self._transport = TCPServerTransport(port=tcp_port)
            else:
                self._transport = default_server_transport()

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------

    @staticmethod
    def default_socket_path() -> Path:
        """Return socket path from ``AVAKILL_SOCKET`` or ``~/.avakill/avakill.sock``."""
        env = os.environ.get("AVAKILL_SOCKET")
        if env:
            return Path(env)
        return Path.home() / ".avakill" / "avakill.sock"

    @staticmethod
    def default_pid_path() -> Path:
        """Return PID file path: ``~/.avakill/avakill.pid``."""
        return Path.home() / ".avakill" / "avakill.pid"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create the socket/listener and begin accepting connections.

        - Delegates binding to the transport
        - Writes a PID file
        - Installs SIGTERM/SIGINT handlers for graceful shutdown
        - Installs SIGHUP handler for policy reload (Unix only)
        """
        self._stop_event = asyncio.Event()
        self._conn_semaphore = asyncio.Semaphore(self._max_connections)

        self._server = await self._transport.start(
            self._handle_connection, limit=_MAX_REQUEST_SIZE
        )

        # PID file
        self._pid_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_path.write_text(str(os.getpid()))

        # Signal handlers (Unix only — Windows uses signal.signal() in CLI)
        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            with contextlib.suppress(RuntimeError):
                for sig in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(sig, self._request_stop)
                loop.add_signal_handler(signal.SIGHUP, self._request_reload)

        logger.info(
            "AvaKill daemon started on %s (PID %d)",
            self._transport.display_address(),
            os.getpid(),
        )

    async def stop(self) -> None:
        """Close the server and clean up transport artifacts + PID file."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        await self._transport.cleanup()

        if self._pid_path.exists():
            self._pid_path.unlink(missing_ok=True)

        logger.info("AvaKill daemon stopped.")

    async def serve_forever(self) -> None:
        """Start and block until a stop signal is received."""
        await self.start()
        assert self._stop_event is not None
        try:
            await self._stop_event.wait()
        finally:
            await self.stop()

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client: read request, evaluate, write response, close."""
        assert self._conn_semaphore is not None
        try:
            try:
                await asyncio.wait_for(
                    self._conn_semaphore.acquire(), timeout=_CONNECTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Connection rejected: server at capacity (%d).",
                    self._max_connections,
                )
                resp = EvaluateResponse(decision="deny", reason="server at capacity")
                writer.write(serialize_response(resp))
                await writer.drain()
                return

            try:
                raw = await asyncio.wait_for(reader.readline(), timeout=_CONNECTION_TIMEOUT)
                if not raw:
                    return

                try:
                    req = deserialize_request(raw)
                except ValueError as exc:
                    resp = EvaluateResponse(decision="deny", reason=f"malformed request: {exc}")
                    writer.write(serialize_response(resp))
                    await writer.drain()
                    return

                resp = self._evaluate(req)
                writer.write(serialize_response(resp))
                await writer.drain()
            finally:
                self._conn_semaphore.release()

        except asyncio.TimeoutError:
            logger.debug("Client connection timed out.")
        except (asyncio.LimitOverrunError, ValueError):
            logger.warning("Request exceeded %d-byte limit; denied.", _MAX_REQUEST_SIZE)
            with contextlib.suppress(Exception):
                resp = EvaluateResponse(decision="deny", reason="request too large")
                writer.write(serialize_response(resp))
                await writer.drain()
        except asyncio.IncompleteReadError:
            logger.warning("Incomplete read from client; denied.")
            with contextlib.suppress(Exception):
                resp = EvaluateResponse(decision="deny", reason="incomplete request")
                writer.write(serialize_response(resp))
                await writer.drain()
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            logger.debug("Client connection error: %s", exc)
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, req: EvaluateRequest) -> EvaluateResponse:
        """Translate an :class:`EvaluateRequest` into a Guard evaluation."""
        canonical_tool = self._normalizer.normalize(req.tool, req.agent)
        try:
            decision = self._guard.evaluate(
                tool=canonical_tool,
                args=req.args,
                agent_id=req.agent,
                session_id=req.context.get("session_id"),
                metadata=req.context,
            )
        except RateLimitExceeded as exc:
            decision = exc.decision

        return EvaluateResponse(
            decision=decision.action,
            reason=decision.reason,
            policy=decision.policy_name,
            latency_ms=decision.latency_ms,
        )

    # ------------------------------------------------------------------
    # Signal helpers
    # ------------------------------------------------------------------

    def _request_stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    def _request_reload(self) -> None:
        logger.info("SIGHUP received — reloading policy.")
        with contextlib.suppress(Exception):
            self._guard.reload_policy()

    # ------------------------------------------------------------------
    # Process queries
    # ------------------------------------------------------------------

    @staticmethod
    def is_running(pid_file: str | Path | None = None) -> tuple[bool, int | None]:
        """Check whether a daemon is already running.

        Returns:
            ``(True, pid)`` if a live process matches the PID file,
            ``(False, None)`` otherwise.
        """
        path = Path(pid_file) if pid_file else DaemonServer.default_pid_path()
        if not path.exists():
            return False, None
        try:
            pid = int(path.read_text().strip())
            os.kill(pid, 0)  # signal 0 = existence check
            return True, pid
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            return False, None
