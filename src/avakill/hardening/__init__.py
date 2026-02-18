"""OS-level hardening utilities for AvaKill policy files."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def check_immutable(path: str | Path) -> bool:
    """Check if a file has the OS-level immutable flag set.

    On Linux: uses FS_IOC_GETFLAGS ioctl to check EXT2_IMMUTABLE_FL.
    On macOS: checks SF_IMMUTABLE/UF_IMMUTABLE via os.stat st_flags.
    On other platforms or on error: returns False.
    """
    path = Path(path)
    if not path.exists():
        return False

    if sys.platform == "linux":
        return _check_immutable_linux(path)
    elif sys.platform == "darwin":
        return _check_immutable_macos(path)
    return False


def _check_immutable_linux(path: Path) -> bool:
    """Check immutable flag on Linux using ioctl."""
    try:
        import fcntl
        import struct

        FS_IOC_GETFLAGS = 0x80086601
        EXT2_IMMUTABLE_FL = 0x00000010

        fd = os.open(str(path), os.O_RDONLY)
        try:
            buf = struct.pack("l", 0)
            result = fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
            flags = struct.unpack("l", result)[0]
            return bool(flags & EXT2_IMMUTABLE_FL)
        finally:
            os.close(fd)
    except (OSError, ImportError):
        return False


def _check_immutable_macos(path: Path) -> bool:
    """Check immutable flag on macOS using stat flags."""
    try:
        st = os.stat(str(path))
        SF_IMMUTABLE = 0x00020000
        UF_IMMUTABLE = 0x00000002
        return bool(st.st_flags & (SF_IMMUTABLE | UF_IMMUTABLE))
    except (OSError, AttributeError):
        return False


def check_file_permissions(path: str | Path) -> dict:
    """Check file permissions and ownership.

    Returns:
        Dict with mode (octal string), uid, gid, writable_by_others (bool).
    """
    path = Path(path)
    st = os.stat(str(path))
    return {
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "writable_by_others": bool(st.st_mode & stat.S_IWOTH),
    }


def get_template_path(name: str) -> Path:
    """Return the path to a bundled hardening template."""
    return Path(__file__).parent / name


def get_template_content(name: str) -> str:
    """Read and return the content of a bundled hardening template.

    Raises:
        FileNotFoundError: If the template does not exist.
    """
    path = get_template_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Template not found: {name}")
    return path.read_text()


def set_immutable_linux(path: str | Path) -> None:
    """Set the Linux immutable flag (chattr +i) on a file.

    Requires CAP_LINUX_IMMUTABLE (typically root).

    Raises:
        OSError: If the ioctl call fails.
    """
    import fcntl
    import struct

    FS_IOC_GETFLAGS = 0x80086601
    FS_IOC_SETFLAGS = 0x40086602
    EXT2_IMMUTABLE_FL = 0x00000010

    fd = os.open(str(path), os.O_RDONLY)
    try:
        buf = struct.pack("l", 0)
        result = fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
        flags = struct.unpack("l", result)[0]
        flags |= EXT2_IMMUTABLE_FL
        buf = struct.pack("l", flags)
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, buf)
    finally:
        os.close(fd)


def set_immutable_macos(path: str | Path) -> None:
    """Set the macOS system immutable flag (chflags schg) on a file.

    Requires root. Clearable only in single-user mode.

    Raises:
        subprocess.CalledProcessError: If chflags fails.
    """
    import subprocess

    subprocess.run(
        ["chflags", "schg", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
