"""Synchronous client for the AvaKill daemon.

Uses stdlib :mod:`socket` (no asyncio) so that hook scripts — which are
short-lived processes — can evaluate a tool call with minimal overhead.
Falls back to a deny decision if the daemon is unreachable (fail-closed).
"""

from __future__ import annotations

import socket as _socket
from pathlib import Path
from typing import Any

from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_response,
    serialize_request,
)
from avakill.daemon.server import DaemonServer


class DaemonClient:
    """Synchronous client that talks to a running :class:`DaemonServer`.

    Usage::

        client = DaemonClient()
        resp = client.evaluate(EvaluateRequest(agent="cli", tool="Bash", args={...}))
        if resp.decision == "deny":
            print(resp.reason)
    """

    def __init__(
        self,
        socket_path: str | Path | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._socket_path = str(socket_path or DaemonServer.default_socket_path())
        self._timeout = timeout

    def evaluate(self, request: EvaluateRequest) -> EvaluateResponse:
        """Send an evaluation request and return the response.

        Returns a deny response on any communication error (fail-closed).
        """
        try:
            return self._send(request)
        except Exception as exc:  # noqa: BLE001
            return EvaluateResponse(
                decision="deny",
                reason=f"daemon unavailable: {exc}",
            )

    def ping(self) -> bool:
        """Check if the daemon is reachable by sending a minimal request."""
        try:
            self._send(EvaluateRequest(agent="ping", tool="__ping__"))
            return True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send(self, request: EvaluateRequest) -> EvaluateResponse:
        """Low-level send/receive over the Unix socket."""
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(self._socket_path)
            sock.sendall(serialize_request(request))
            sock.shutdown(_socket.SHUT_WR)  # signal EOF to server

            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

            raw = b"".join(chunks)
            if not raw.strip():
                return EvaluateResponse(decision="deny", reason="empty response from daemon")
            return deserialize_response(raw)
        finally:
            sock.close()
