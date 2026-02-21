"""Synchronous client for the AvaKill daemon.

Uses stdlib :mod:`socket` (no asyncio) so that hook scripts — which are
short-lived processes — can evaluate a tool call with minimal overhead.
Falls back to a deny decision if the daemon is unreachable (fail-closed),
or returns ``None`` via :meth:`~DaemonClient.try_evaluate` for soft fallback.
"""

from __future__ import annotations

import socket as _socket
from pathlib import Path
from typing import TYPE_CHECKING

from avakill.daemon.protocol import (
    EvaluateRequest,
    EvaluateResponse,
    deserialize_response,
    serialize_request,
)

if TYPE_CHECKING:
    from avakill.daemon.transport import ClientTransport


class DaemonClient:
    """Synchronous client that talks to a running :class:`DaemonServer`.

    Supports both Unix domain sockets (Linux/macOS) and TCP localhost
    (Windows) via the transport abstraction.

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
        transport: ClientTransport | None = None,
        tcp_port: int | None = None,
    ) -> None:
        self._timeout = timeout

        if transport is not None:
            self._transport = transport
        else:
            from avakill.daemon.transport import (
                TCPClientTransport,
                UnixClientTransport,
                default_client_transport,
            )

            if socket_path is not None:
                self._transport = UnixClientTransport(Path(socket_path))
            elif tcp_port is not None:
                self._transport = TCPClientTransport(port=tcp_port)
            else:
                self._transport = default_client_transport()

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

    def try_evaluate(self, request: EvaluateRequest) -> EvaluateResponse | None:
        """Send an evaluation request, returning ``None`` if the daemon is unreachable.

        Unlike :meth:`evaluate`, this does **not** synthesize a deny response
        on connection failure — it returns ``None`` so the caller can fall
        through to the next evaluation strategy.
        """
        try:
            return self._send(request)
        except Exception:  # noqa: BLE001
            return None

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
        """Low-level send/receive over the transport."""
        sock = self._transport.connect(self._timeout)
        try:
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
