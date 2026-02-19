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

# ABI v2 filesystem flags
LANDLOCK_ACCESS_FS_REFER = 1 << 13

# ABI v3 filesystem flags
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

# ABI v5 filesystem flags
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15

LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2

# Network access flags (ABI v4+)
LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

# Flags for landlock_create_ruleset
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

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

# Map path access types to Landlock filesystem flags
PATH_ACCESS_MAP: dict[str, int] = {
    "read": LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    "write": (
        LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
    ),
    "execute": LANDLOCK_ACCESS_FS_EXECUTE,
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


class LandlockNetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
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

    @staticmethod
    def abi_version() -> int:
        """Detect highest supported Landlock ABI version (1-6+).

        Calls landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
        Returns 0 if Landlock is unavailable.
        """
        if sys.platform != "linux":
            return 0
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            result = libc.syscall(
                LANDLOCK_CREATE_RULESET,
                None,
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
            return result if result >= 0 else 0
        except (OSError, AttributeError):
            return 0

    @staticmethod
    def supported_features(abi: int) -> dict[str, bool]:
        """Return feature availability for a given ABI version.

        Returns:
            Dictionary mapping feature names to availability booleans.
        """
        return {
            "filesystem": abi >= 1,
            "file_refer": abi >= 2,
            "file_truncate": abi >= 3,
            "network_tcp": abi >= 4,
            "device_ioctl": abi >= 5,
            "ipc_scoping": abi >= 6,
        }

    @staticmethod
    def _max_fs_flags(abi: int) -> int:
        """Return maximum filesystem flags supported by the given ABI version."""
        flags = ALL_ACCESS_FS  # ABI 1
        if abi >= 2:
            flags |= LANDLOCK_ACCESS_FS_REFER
        if abi >= 3:
            flags |= LANDLOCK_ACCESS_FS_TRUNCATE
        if abi >= 5:
            flags |= LANDLOCK_ACCESS_FS_IOCTL_DEV
        return flags

    def generate_ruleset(self, config: PolicyConfig) -> dict[str, Any]:
        """Generate a ruleset description from deny rules (dry-run output).

        Args:
            config: The policy configuration to translate.

        Returns:
            A dictionary describing the Landlock ruleset that would be
            applied, including restricted access flags, ABI version,
            supported features, and their sources.
        """
        abi = self.abi_version()
        features = self.supported_features(abi)

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

        # Mask to ABI-supported flags when Landlock is available
        if abi > 0:
            restricted_flags &= self._max_fs_flags(abi)

        return {
            "landlock_abi": abi,
            "handled_access_fs": restricted_flags,
            "restricted_flag_names": self._flag_names(restricted_flags),
            "sources": sources,
            "supported_features": features,
        }

    def apply(self, config: PolicyConfig) -> None:
        """Apply Landlock restrictions to the current process.

        Maps deny rules to filesystem access restrictions and applies
        them using the Landlock syscalls. Once applied, restrictions
        cannot be removed for the lifetime of the process.

        Flags are masked to the detected ABI version for graceful
        degradation on older kernels.

        Args:
            config: The policy configuration to enforce.

        Raises:
            RuntimeError: If Landlock is not available or syscalls fail.
        """
        if not self.available():
            raise RuntimeError("Landlock is not available on this system")

        abi = self.abi_version()
        ruleset = self.generate_ruleset(config)
        restricted_flags = ruleset["handled_access_fs"]

        # Mask to ABI-supported flags for graceful degradation
        if abi > 0:
            restricted_flags &= self._max_fs_flags(abi)

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

    def apply_path_rules(
        self,
        ruleset_fd: int,
        allow_paths: dict[str, list[str]],
        handled_flags: int,
    ) -> None:
        """Add per-path Landlock rules to an existing ruleset.

        For each path in allow_paths, opens the directory and adds a
        LANDLOCK_RULE_PATH_BENEATH rule with the appropriate access flags.

        Args:
            ruleset_fd: File descriptor of the Landlock ruleset.
            allow_paths: Mapping of access type ("read", "write", "execute")
                to list of allowed paths. Paths may use ~ for home directory.
            handled_flags: The handled_access_fs flags for this ruleset,
                used to intersect with requested access.
        """
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        for access_type, paths in allow_paths.items():
            base_flags = PATH_ACCESS_MAP.get(access_type, 0)
            if not base_flags:
                continue
            # Only grant flags that are actually handled by this ruleset
            allowed_access = base_flags & handled_flags
            if not allowed_access:
                continue

            for raw_path in paths:
                path = os.path.expanduser(raw_path)
                if not os.path.exists(path):
                    continue
                try:
                    fd = os.open(path, os.O_PATH | os.O_DIRECTORY)  # type: ignore[attr-defined]
                except OSError:
                    # Path exists but can't be opened as directory — try as file
                    try:
                        fd = os.open(path, os.O_PATH)  # type: ignore[attr-defined]
                    except OSError:
                        continue
                try:
                    path_attr = LandlockPathBeneathAttr(
                        allowed_access=allowed_access,
                        parent_fd=fd,
                    )
                    libc.syscall(
                        LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(path_attr),
                        0,
                    )
                finally:
                    os.close(fd)

    def apply_network_rules(
        self,
        ruleset_fd: int,
        connect_ports: list[int] | None = None,
        bind_ports: list[int] | None = None,
    ) -> None:
        """Add per-port Landlock network rules (requires ABI 4+).

        Args:
            ruleset_fd: File descriptor of the Landlock ruleset.
            connect_ports: Ports to allow outbound TCP connections.
            bind_ports: Ports to allow TCP binding.
        """
        abi = self.abi_version()
        if abi < 4:
            return  # Network rules not supported below ABI 4

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        for port in connect_ports or []:
            net_attr = LandlockNetPortAttr(
                allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port=port,
            )
            libc.syscall(
                LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                ctypes.byref(net_attr),
                0,
            )

        for port in bind_ports or []:
            net_attr = LandlockNetPortAttr(
                allowed_access=LANDLOCK_ACCESS_NET_BIND_TCP,
                port=port,
            )
            libc.syscall(
                LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                ctypes.byref(net_attr),
                0,
            )

    def apply_to_child(
        self,
        *,
        read_paths: list[str],
        write_paths: list[str],
        exec_paths: list[str],
        connect_ports: list[int] | None = None,
        abi_version: int | None = None,
    ) -> None:
        """Apply Landlock restrictions for a child process (preexec_fn).

        Unlike apply() which restricts based on deny rules, this method
        builds an allow-based sandbox from explicit path and port lists.
        Designed to be called from preexec_fn - only uses async-signal-safe
        operations via ctypes.
        """
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        abi = abi_version or self.abi_version()

        handled_fs = ALL_ACCESS_FS
        if abi >= 2:
            handled_fs |= LANDLOCK_ACCESS_FS_REFER
        if abi >= 3:
            handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE

        handled_net = 0
        if abi >= 4 and connect_ports:
            handled_net = LANDLOCK_ACCESS_NET_CONNECT_TCP

        PR_SET_NO_NEW_PRIVS = 38  # noqa: N806
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        attr = LandlockRulesetAttr(
            handled_access_fs=handled_fs,
            handled_access_net=handled_net,
        )
        ruleset_fd = libc.syscall(
            LANDLOCK_CREATE_RULESET,
            ctypes.byref(attr),
            ctypes.sizeof(attr),
            0,
        )
        if ruleset_fd < 0:
            os._exit(126)

        try:
            read_flags = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
            write_flags = (
                LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_FILE
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
            )

            self._add_path_rules_child(libc, ruleset_fd, read_paths, read_flags)
            self._add_path_rules_child(libc, ruleset_fd, write_paths, write_flags)
            self._add_path_rules_child(libc, ruleset_fd, exec_paths, LANDLOCK_ACCESS_FS_EXECUTE)

            if handled_net and connect_ports:
                self._add_network_rules_child(libc, ruleset_fd, connect_ports)

            result = libc.syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
            if result < 0:
                os._exit(126)
        finally:
            os.close(ruleset_fd)

    def _add_path_rules_child(
        self,
        libc: Any,
        ruleset_fd: int,
        paths: list[str],
        access_flags: int,
    ) -> None:
        """Add per-path Landlock rules. Safe for preexec_fn context."""
        for path_str in paths:
            try:
                fd = os.open(path_str, os.O_PATH | os.O_DIRECTORY)  # type: ignore[attr-defined]
            except OSError:
                continue
            try:
                path_attr = LandlockPathBeneathAttr(
                    allowed_access=access_flags,
                    parent_fd=fd,
                )
                libc.syscall(
                    LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(path_attr),
                    0,
                )
            finally:
                os.close(fd)

    def _add_network_rules_child(
        self,
        libc: Any,
        ruleset_fd: int,
        ports: list[int],
    ) -> None:
        """Add per-port Landlock network rules (ABI 4+). Safe for preexec_fn."""
        for port in ports:
            net_attr = LandlockNetPortAttr(
                allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port=port,
            )
            libc.syscall(
                LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                ctypes.byref(net_attr),
                0,
            )

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
            LANDLOCK_ACCESS_FS_REFER: "REFER",
            LANDLOCK_ACCESS_FS_TRUNCATE: "TRUNCATE",
            LANDLOCK_ACCESS_FS_IOCTL_DEV: "IOCTL_DEV",
        }
        for bit, name in flag_map.items():
            if flags & bit:
                names.append(name)
        return names
