"""Persistent AvaKill daemon over a Unix domain socket.

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

from avakill.core.engine import Guard
from avakill.core.exceptions import RateLimitExceeded
from avakill.core.normalization import ToolNormalizer
from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_request,
    serialize_response,
)

logger = logging.getLogger("avakill.daemon")

_CONNECTION_TIMEOUT = 5.0  # seconds


class DaemonServer:
    """Asyncio Unix-socket server wrapping :class:`Guard`.

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
    ) -> None:
        self._guard = guard
        self._socket_path = Path(socket_path) if socket_path else self.default_socket_path()
        self._pid_path = Path(pid_file) if pid_file else self.default_pid_path()
        self._normalizer = normalizer or ToolNormalizer()
        self._server: asyncio.AbstractServer | None = None
        self._stop_event: asyncio.Event | None = None

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
        """Create the socket and begin accepting connections.

        - Creates parent directory for the socket
        - Removes stale socket file if present
        - Writes a PID file
        - Installs SIGTERM/SIGINT handlers for graceful shutdown
        - Installs SIGHUP handler for policy reload
        """
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        if self._socket_path.exists():
            self._socket_path.unlink()

        self._stop_event = asyncio.Event()

        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(self._socket_path),
        )

        # PID file
        self._pid_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_path.write_text(str(os.getpid()))

        # Signal handlers (only if running in the main thread)
        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            with contextlib.suppress(RuntimeError):
                for sig in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(sig, self._request_stop)
                loop.add_signal_handler(signal.SIGHUP, self._request_reload)

        logger.info("AvaKill daemon started on %s (PID %d)", self._socket_path, os.getpid())

    async def stop(self) -> None:
        """Close the server and clean up socket + PID files."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        if self._socket_path.exists():
            self._socket_path.unlink(missing_ok=True)

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

        except asyncio.TimeoutError:
            logger.debug("Client connection timed out.")
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
