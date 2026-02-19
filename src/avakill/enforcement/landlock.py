"""Landlock-based filesystem restriction (Linux 5.13+, unprivileged).

Translates AvaKill deny rules into Landlock access restrictions.
Uses ctypes for landlock_create_ruleset/add_rule/restrict_self syscalls.

Reference: https://docs.kernel.org/userspace-api/landlock.html
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from typing import Any

from avakill.core.models import PolicyConfig

# Landlock ABI version 1 constants
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_ADD_RULE = 445
LANDLOCK_RESTRICT_SELF = 446

# Access filesystem flags (ABI v1)
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12

LANDLOCK_RULE_PATH_BENEATH = 1

# Map canonical tool names to Landlock access flags to restrict
TOOL_TO_ACCESS_FLAGS: dict[str, int] = {
    "file_write": (
        LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    ),
    "file_delete": LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR,
    "file_edit": LANDLOCK_ACCESS_FS_WRITE_FILE,
    "shell_execute": LANDLOCK_ACCESS_FS_EXECUTE,
}

# All filesystem access rights combined (for ruleset creation)
ALL_ACCESS_FS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
)


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class LandlockEnforcer:
    """Landlock-based filesystem restriction (Linux 5.13+, unprivileged).

    Translates AvaKill deny rules into Landlock access restrictions.
    """

    @staticmethod
    def available() -> bool:
        """Check if Landlock is available on this system.

        Returns True only on Linux with kernel 5.13+ that supports
        the landlock_create_ruleset syscall.
        """
        if sys.platform != "linux":
            return False
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            attr = LandlockRulesetAttr(handled_access_fs=0, handled_access_net=0)
            result = libc.syscall(
                LANDLOCK_CREATE_RULESET,
                ctypes.byref(attr),
                ctypes.sizeof(attr),
                0,
            )
            if result >= 0:
                os.close(result)
                return True
            return False
        except (OSError, AttributeError):
            return False

    def generate_ruleset(self, config: PolicyConfig) -> dict[str, Any]:
        """Generate a ruleset description from deny rules (dry-run output).

        Args:
            config: The policy configuration to translate.

        Returns:
            A dictionary describing the Landlock ruleset that would be
            applied, including restricted access flags and their sources.
        """
        restricted_flags = 0
        sources: list[dict[str, Any]] = []

        for rule in config.policies:
            if rule.action != "deny":
                continue
            for tool_pattern in rule.tools:
                flags = self._tool_pattern_to_flags(tool_pattern)
                if flags:
                    restricted_flags |= flags
                    sources.append(
                        {
                            "rule": rule.name,
                            "tool_pattern": tool_pattern,
                            "flags": flags,
                            "flag_names": self._flag_names(flags),
                        }
                    )

        return {
            "landlock_abi": 1,
            "handled_access_fs": restricted_flags,
            "restricted_flag_names": self._flag_names(restricted_flags),
            "sources": sources,
        }

    def apply(self, config: PolicyConfig) -> None:
        """Apply Landlock restrictions to the current process.

        Maps deny rules to filesystem access restrictions and applies
        them using the Landlock syscalls. Once applied, restrictions
        cannot be removed for the lifetime of the process.

        Args:
            config: The policy configuration to enforce.

        Raises:
            RuntimeError: If Landlock is not available or syscalls fail.
        """
        if not self.available():
            raise RuntimeError("Landlock is not available on this system")

        ruleset = self.generate_ruleset(config)
        restricted_flags = ruleset["handled_access_fs"]

        if restricted_flags == 0:
            return  # Nothing to restrict

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # Create ruleset
        attr = LandlockRulesetAttr(
            handled_access_fs=restricted_flags,
            handled_access_net=0,
        )
        ruleset_fd = libc.syscall(
            LANDLOCK_CREATE_RULESET,
            ctypes.byref(attr),
            ctypes.sizeof(attr),
            0,
        )
        if ruleset_fd < 0:
            errno = ctypes.get_errno()
            raise RuntimeError(f"landlock_create_ruleset failed: errno {errno}")

        try:
            # Add a rule allowing read access to root so the process can still function.
            # The restricted_flags determine what's *handled*; we add path rules
            # to grant back specific access.
            allowed_access = ALL_ACCESS_FS & ~restricted_flags
            if allowed_access:
                root_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)  # type: ignore[attr-defined]
                try:
                    path_attr = LandlockPathBeneathAttr(
                        allowed_access=allowed_access,
                        parent_fd=root_fd,
                    )
                    result = libc.syscall(
                        LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(path_attr),
                        0,
                    )
                    if result < 0:
                        errno = ctypes.get_errno()
                        raise RuntimeError(f"landlock_add_rule failed: errno {errno}")
                finally:
                    os.close(root_fd)

            # Restrict self
            # First call prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            PR_SET_NO_NEW_PRIVS = 38
            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

            result = libc.syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
            if result < 0:
                errno = ctypes.get_errno()
                raise RuntimeError(f"landlock_restrict_self failed: errno {errno}")
        finally:
            os.close(ruleset_fd)

    def _tool_pattern_to_flags(self, tool_pattern: str) -> int:
        """Convert a tool name pattern to Landlock access flags."""
        # Check for exact matches
        if tool_pattern in TOOL_TO_ACCESS_FLAGS:
            return TOOL_TO_ACCESS_FLAGS[tool_pattern]

        # Wildcard or "all" — restrict everything
        if tool_pattern in ("*", "all"):
            return ALL_ACCESS_FS

        # Check glob-style patterns (e.g. "file_*" matches file_write, file_delete)
        from fnmatch import fnmatch

        flags = 0
        for tool_name, tool_flags in TOOL_TO_ACCESS_FLAGS.items():
            if fnmatch(tool_name, tool_pattern):
                flags |= tool_flags
        return flags

    @staticmethod
    def _flag_names(flags: int) -> list[str]:
        """Convert flag bits to human-readable names."""
        names = []
        flag_map = {
            LANDLOCK_ACCESS_FS_EXECUTE: "EXECUTE",
            LANDLOCK_ACCESS_FS_WRITE_FILE: "WRITE_FILE",
            LANDLOCK_ACCESS_FS_READ_FILE: "READ_FILE",
            LANDLOCK_ACCESS_FS_READ_DIR: "READ_DIR",
            LANDLOCK_ACCESS_FS_REMOVE_DIR: "REMOVE_DIR",
            LANDLOCK_ACCESS_FS_REMOVE_FILE: "REMOVE_FILE",
            LANDLOCK_ACCESS_FS_MAKE_CHAR: "MAKE_CHAR",
            LANDLOCK_ACCESS_FS_MAKE_DIR: "MAKE_DIR",
            LANDLOCK_ACCESS_FS_MAKE_REG: "MAKE_REG",
            LANDLOCK_ACCESS_FS_MAKE_SOCK: "MAKE_SOCK",
            LANDLOCK_ACCESS_FS_MAKE_FIFO: "MAKE_FIFO",
            LANDLOCK_ACCESS_FS_MAKE_BLOCK: "MAKE_BLOCK",
            LANDLOCK_ACCESS_FS_MAKE_SYM: "MAKE_SYM",
        }
        for bit, name in flag_map.items():
            if flags & bit:
                names.append(name)
        return names
