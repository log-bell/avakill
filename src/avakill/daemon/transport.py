"""Transport abstraction for the AvaKill daemon.

Provides Unix domain socket transport (Linux/macOS) and TCP localhost
transport (Windows, or any platform via explicit opt-in).
"""

from __future__ import annotations

import asyncio
import socket as _socket
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

# Type alias for the asyncio client-connected callback.
_ConnectionHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter],
    Coroutine[Any, Any, None],
]

DEFAULT_TCP_PORT = 19426


# ---------------------------------------------------------------------------
# Server transports
# ---------------------------------------------------------------------------


class ServerTransport(ABC):
    """Abstract base for daemon server transports."""

    @abstractmethod
    async def start(
        self, handler: _ConnectionHandler, *, limit: int = 65536
    ) -> asyncio.AbstractServer:
        """Bind and start listening, returning the asyncio server."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Remove any filesystem artifacts (socket file, port file, etc.)."""

    @abstractmethod
    def display_address(self) -> str:
        """Human-readable address string for status output."""


class UnixServerTransport(ServerTransport):
    """Unix domain socket server transport."""

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path

    async def start(
        self, handler: _ConnectionHandler, *, limit: int = 65536
    ) -> asyncio.AbstractServer:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self._socket_path.exists():
            self._socket_path.unlink()
        return await asyncio.start_unix_server(handler, path=str(self._socket_path), limit=limit)

    async def cleanup(self) -> None:
        if self._socket_path.exists():
            self._socket_path.unlink(missing_ok=True)

    def display_address(self) -> str:
        return str(self._socket_path)

    @property
    def socket_path(self) -> Path:
        return self._socket_path


class TCPServerTransport(ServerTransport):
    """TCP localhost server transport (primarily for Windows)."""

    def __init__(self, port: int = DEFAULT_TCP_PORT, port_file: Path | None = None) -> None:
        self._requested_port = port
        self._actual_port: int | None = None
        self._port_file = port_file or _default_port_file()

    async def start(
        self, handler: _ConnectionHandler, *, limit: int = 65536
    ) -> asyncio.AbstractServer:
        server = await asyncio.start_server(
            handler, host="127.0.0.1", port=self._requested_port, limit=limit
        )
        # Resolve actual port (important when requested_port=0 for tests).
        sock = server.sockets[0]
        self._actual_port = sock.getsockname()[1]
        # Write port file so clients can discover us.
        self._port_file.parent.mkdir(parents=True, exist_ok=True)
        self._port_file.write_text(str(self._actual_port))
        return server

    async def cleanup(self) -> None:
        if self._port_file.exists():
            self._port_file.unlink(missing_ok=True)

    def display_address(self) -> str:
        port = self._actual_port or self._requested_port
        return f"127.0.0.1:{port}"

    @property
    def port(self) -> int | None:
        return self._actual_port

    @property
    def port_file(self) -> Path:
        return self._port_file


# ---------------------------------------------------------------------------
# Client transports
# ---------------------------------------------------------------------------


class ClientTransport(ABC):
    """Abstract base for daemon client transports."""

    @abstractmethod
    def connect(self, timeout: float) -> _socket.socket:
        """Create a connected socket ready for send/recv."""


class UnixClientTransport(ClientTransport):
    """Unix domain socket client transport."""

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path

    def connect(self, timeout: float) -> _socket.socket:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(self._socket_path))
        return sock


class TCPClientTransport(ClientTransport):
    """TCP localhost client transport (primarily for Windows)."""

    def __init__(self, port: int | None = None, port_file: Path | None = None) -> None:
        self._port = port
        self._port_file = port_file or _default_port_file()

    def connect(self, timeout: float) -> _socket.socket:
        port = self._port or self._read_port_file()
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        return sock

    def _read_port_file(self) -> int:
        if not self._port_file.exists():
            raise ConnectionError(
                f"Daemon port file not found: {self._port_file}. Is the daemon running?"
            )
        try:
            return int(self._port_file.read_text().strip())
        except (ValueError, OSError) as exc:
            raise ConnectionError(f"Cannot read daemon port file: {exc}") from exc


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def _default_port_file() -> Path:
    """Return ``~/.avakill/avakill.port``."""
    return Path.home() / ".avakill" / "avakill.port"


def default_server_transport(
    socket_path: Path | None = None,
    tcp_port: int | None = None,
) -> ServerTransport:
    """Return the platform-appropriate server transport.

    - On Windows: always TCP.
    - On Unix: TCP if ``tcp_port`` is explicitly provided, otherwise Unix socket.
    """
    if sys.platform == "win32":
        return TCPServerTransport(port=tcp_port or DEFAULT_TCP_PORT)
    if tcp_port is not None:
        return TCPServerTransport(port=tcp_port)
    from avakill.daemon.server import DaemonServer

    return UnixServerTransport(socket_path or DaemonServer.default_socket_path())


def default_client_transport(
    socket_path: Path | None = None,
    tcp_port: int | None = None,
) -> ClientTransport:
    """Return the platform-appropriate client transport.

    - On Windows: always TCP.
    - On Unix: TCP if ``tcp_port`` is explicitly provided, otherwise Unix socket.
    """
    if sys.platform == "win32":
        return TCPClientTransport(port=tcp_port)
    if tcp_port is not None:
        return TCPClientTransport(port=tcp_port)
    from avakill.daemon.server import DaemonServer

    return UnixClientTransport(socket_path or DaemonServer.default_socket_path())
