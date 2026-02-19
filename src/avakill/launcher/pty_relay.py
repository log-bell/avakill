"""PTY allocation and I/O relay for interactive sandboxed processes.

Used by ProcessLauncher when --pty is specified. Allocates a PTY pair,
attaches the slave end to the child process, and relays the master end
to the parent's stdin/stdout. Handles SIGWINCH for terminal resize.
"""

from __future__ import annotations

import errno
import fcntl
import os
import select
import signal
import subprocess
import sys
import termios
import tty
from typing import Any


class PTYRelay:
    """Relay I/O between a PTY master and the parent terminal.

    Used by ProcessLauncher when --pty is specified. Allocates a PTY pair,
    attaches the slave end to the child process, and relays the master end
    to the parent's stdin/stdout. Handles SIGWINCH for terminal resize.
    """

    def __init__(self) -> None:
        self._master_fd: int | None = None
        self._old_settings: list[Any] | None = None
        self._old_sigwinch: Any = None

    def allocate(self) -> tuple[int, int]:
        """Allocate master/slave PTY pair via os.openpty().

        Returns:
            Tuple of (master_fd, slave_fd).
        """
        master_fd, slave_fd = os.openpty()
        self._master_fd = master_fd

        # Copy parent terminal size to slave
        if sys.stdin.isatty():
            winsize = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

        return master_fd, slave_fd

    def relay(self, master_fd: int, process: subprocess.Popen) -> int:
        """Main relay loop using select(). Returns child exit code.

        Relays data between the parent's stdin/stdout and the PTY master.
        Sets the parent terminal to raw mode for passthrough.

        Args:
            master_fd: The master side of the PTY pair.
            process: The child subprocess using the slave PTY.

        Returns:
            Child process exit code.
        """
        self._master_fd = master_fd
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()

        # Save terminal settings and switch to raw mode
        if sys.stdin.isatty():
            self._old_settings = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)

        # Install SIGWINCH handler
        self._old_sigwinch = signal.signal(signal.SIGWINCH, self._handle_sigwinch)

        try:
            while True:
                # Check if child has exited
                ret = process.poll()
                if ret is not None:
                    # Drain remaining output
                    self._drain(master_fd, stdout_fd)
                    return ret

                try:
                    fds = [master_fd]
                    if sys.stdin.isatty():
                        fds.append(stdin_fd)

                    readable, _, _ = select.select(fds, [], [], 0.1)
                except (OSError, ValueError):
                    # select interrupted or fd closed
                    ret = process.poll()
                    return ret if ret is not None else 128

                for fd in readable:
                    if fd == master_fd:
                        # Data from child -> parent stdout
                        try:
                            data = os.read(master_fd, 4096)
                        except OSError as e:
                            if e.errno == errno.EIO:
                                # Child closed PTY
                                process.wait()
                                return process.returncode or 0
                            raise
                        if data:
                            os.write(stdout_fd, data)
                    elif fd == stdin_fd:
                        # Data from parent stdin -> child
                        data = os.read(stdin_fd, 4096)
                        if data:
                            os.write(master_fd, data)
        finally:
            # Restore terminal settings
            if self._old_settings is not None:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, self._old_settings)
            if self._old_sigwinch is not None:
                signal.signal(signal.SIGWINCH, self._old_sigwinch)

    def _handle_sigwinch(self, signum: int, frame: Any) -> None:
        """Forward terminal resize to child PTY."""
        if self._master_fd is not None and sys.stdin.isatty():
            winsize = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)

    @staticmethod
    def _drain(master_fd: int, stdout_fd: int) -> None:
        """Drain remaining data from master_fd to stdout_fd."""
        while True:
            try:
                readable, _, _ = select.select([master_fd], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not readable:
                break
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            os.write(stdout_fd, data)
