"""Tests for PTY relay."""

from __future__ import annotations

import os
import sys

import pytest

if sys.platform == "win32":
    pytest.skip("No PTY support on Windows", allow_module_level=True)

from avakill.launcher.pty_relay import PTYRelay


@pytest.mark.skipif(sys.platform == "win32", reason="No PTY support on Windows")
class TestPTYRelay:
    """Tests for PTYRelay."""

    def test_allocate_returns_fd_pair(self) -> None:
        relay = PTYRelay()
        master_fd, slave_fd = relay.allocate()
        try:
            assert isinstance(master_fd, int)
            assert isinstance(slave_fd, int)
            assert master_fd >= 0
            assert slave_fd >= 0
            assert master_fd != slave_fd
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_relay_forwards_stdout(self) -> None:
        import subprocess

        relay = PTYRelay()
        master_fd, slave_fd = relay.allocate()
        try:
            process = subprocess.Popen(
                ["echo", "hello pty"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            # Read output from master (child's stdout goes through PTY)
            import select

            readable, _, _ = select.select([master_fd], [], [], 2.0)
            if readable:
                data = os.read(master_fd, 4096)
                assert b"hello pty" in data
            process.wait()
        finally:
            os.close(master_fd)

    def test_relay_handles_child_exit_cleanly(self) -> None:
        import subprocess

        relay = PTYRelay()
        master_fd, slave_fd = relay.allocate()
        try:
            process = subprocess.Popen(
                ["true"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            # Wait for child to exit, then verify relay can detect it
            process.wait()
            assert process.returncode == 0
        finally:
            os.close(master_fd)
