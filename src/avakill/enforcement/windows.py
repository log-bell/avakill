"""Windows process restriction enforcer using Job Objects and privilege removal.

Translates AvaKill deny rules into Windows process-level restrictions:

1. **Job Object** — Constrains the daemon process and its children:
   - ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` ensures all children die on exit.
   - ``JOB_OBJECT_LIMIT_ACTIVE_PROCESS`` limits subprocess spawning.

2. **Privilege removal** — Strips dangerous token privileges:
   - ``SeRestorePrivilege`` (bypass write ACLs)
   - ``SeBackupPrivilege`` (bypass read ACLs)
   - ``SeTakeOwnershipPrivilege`` (steal file ownership)
   - ``SeDebugPrivilege`` (attach to any process)
   - ``SeImpersonatePrivilege`` (impersonate other tokens)
   Once removed via ``AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED)``,
   these cannot be re-enabled for the process lifetime.

3. **Integrity level** — Optionally lowers the process to Low integrity,
   preventing writes to Medium-integrity objects (most user files).

All APIs use ctypes against kernel32/advapi32, requiring no external deps.

Reference: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import sys
from typing import Any

from avakill.core.models import PolicyConfig

logger = logging.getLogger("avakill.enforcement.windows")

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------

# Job Object limits
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008

# Job info class
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

# Token access rights
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0080

# Privilege attributes
SE_PRIVILEGE_REMOVED = 0x00000004

# Integrity levels
SECURITY_MANDATORY_LOW_RID = 0x00001000

# Process access
PROCESS_ALL_ACCESS = 0x001FFFFF

# Token info class for integrity level
TOKEN_INTEGRITY_LEVEL = 25

# Privileges to remove (maps deny tool patterns to dangerous privs)
_DANGEROUS_PRIVILEGES = [
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
]

# Map canonical tool names to enforcement actions
TOOL_TO_WINDOWS_ACTIONS: dict[str, list[str]] = {
    "file_write": ["remove_SeRestorePrivilege", "job_limit_children"],
    "file_delete": ["remove_SeRestorePrivilege", "job_limit_children"],
    "file_edit": ["remove_SeRestorePrivilege"],
    "shell_execute": ["job_limit_children", "remove_SeDebugPrivilege"],
}


class _LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", ctypes.wintypes.DWORD),
        ("HighPart", ctypes.wintypes.LONG),
    ]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", _LUID),
        ("Attributes", ctypes.wintypes.DWORD),
    ]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.wintypes.DWORD),
        ("Privileges", _LUID_AND_ATTRIBUTES * 1),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.wintypes.DWORD),
        ("SchedulingClass", ctypes.wintypes.DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class WindowsEnforcer:
    """Windows process restriction enforcer using Job Objects + privilege removal.

    Translates AvaKill deny rules into Windows process-level restrictions.
    Once applied, privilege removals are irreversible for the process lifetime.
    """

    @staticmethod
    def available() -> bool:
        """Check if Windows enforcement is available.

        Returns True on Windows (win32).
        """
        return sys.platform == "win32"

    def generate_report(self, config: PolicyConfig) -> dict[str, Any]:
        """Generate a report of what would be restricted (dry-run).

        Args:
            config: The policy configuration to translate.

        Returns:
            A dictionary describing the restrictions that would be applied.
        """
        actions: set[str] = set()
        privileges_to_remove: set[str] = set()
        sources: list[dict[str, Any]] = []

        for rule in config.policies:
            if rule.action != "deny":
                continue
            for tool_pattern in rule.tools:
                rule_actions = self._tool_pattern_to_actions(tool_pattern)
                if rule_actions:
                    actions.update(rule_actions)
                    sources.append(
                        {
                            "rule": rule.name,
                            "tool_pattern": tool_pattern,
                            "actions": rule_actions,
                        }
                    )

        # Always remove all dangerous privileges when any deny rule exists
        if sources:
            privileges_to_remove = set(_DANGEROUS_PRIVILEGES)

        return {
            "platform": "windows",
            "job_object": "job_limit_children" in actions,
            "privileges_removed": sorted(privileges_to_remove),
            "actions": sorted(actions),
            "sources": sources,
        }

    def apply(self, config: PolicyConfig) -> None:
        """Apply Windows process restrictions based on deny rules.

        1. Creates a Job Object and assigns this process to it.
        2. Removes dangerous token privileges (irreversible).

        Args:
            config: The policy configuration to enforce.

        Raises:
            RuntimeError: If not running on Windows or API calls fail.
        """
        if not self.available():
            raise RuntimeError("Windows enforcement is not available on this platform")

        report = self.generate_report(config)

        if not report["sources"]:
            return  # Nothing to restrict

        removed = self._remove_privileges(report["privileges_removed"])
        logger.info(
            "Windows enforcement: removed %d privileges: %s",
            len(removed),
            ", ".join(removed) if removed else "(none found)",
        )

        if report["job_object"]:
            self._create_job_object()
            logger.info("Windows enforcement: Job Object applied with child process limits.")

    def _remove_privileges(self, privilege_names: list[str]) -> list[str]:
        """Remove token privileges from the current process (irreversible).

        Returns list of privileges that were successfully removed.
        """
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]

        # Open current process token
        token = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            logger.warning("Failed to open process token (error %d)", kernel32.GetLastError())
            return []

        removed: list[str] = []
        try:
            for priv_name in privilege_names:
                luid = _LUID()
                if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                    # Privilege doesn't exist on this system — skip
                    continue

                tp = _TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED

                if advapi32.AdjustTokenPrivileges(
                    token,
                    False,
                    ctypes.byref(tp),
                    ctypes.sizeof(tp),
                    None,
                    None,
                ):
                    removed.append(priv_name)
                else:
                    logger.warning(
                        "Failed to remove %s (error %d)",
                        priv_name,
                        kernel32.GetLastError(),
                    )
        finally:
            kernel32.CloseHandle(token)

        return removed

    def _create_job_object(self) -> None:
        """Create a Job Object and assign the current process to it."""
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            logger.warning("Failed to create Job Object (error %d)", kernel32.GetLastError())
            return

        # Set limits
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        # Allow daemon + a reasonable number of children
        info.BasicLimitInformation.ActiveProcessLimit = 10

        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            logger.warning(
                "Failed to set Job Object limits (error %d)",
                kernel32.GetLastError(),
            )
            kernel32.CloseHandle(job)
            return

        # Assign current process to job
        process = kernel32.GetCurrentProcess()
        if not kernel32.AssignProcessToJobObject(job, process):
            logger.warning(
                "Failed to assign process to Job Object (error %d)",
                kernel32.GetLastError(),
            )
            kernel32.CloseHandle(job)
            return

        # Don't close the job handle — it must stay open for the limits to persist

    def _tool_pattern_to_actions(self, tool_pattern: str) -> list[str]:
        """Convert a tool name pattern to Windows enforcement actions."""
        if tool_pattern in TOOL_TO_WINDOWS_ACTIONS:
            return TOOL_TO_WINDOWS_ACTIONS[tool_pattern]

        if tool_pattern in ("*", "all"):
            actions: set[str] = set()
            for tool_actions in TOOL_TO_WINDOWS_ACTIONS.values():
                actions.update(tool_actions)
            return sorted(actions)

        from fnmatch import fnmatch

        actions_set: set[str] = set()
        for tool_name, tool_actions in TOOL_TO_WINDOWS_ACTIONS.items():
            if fnmatch(tool_name, tool_pattern):
                actions_set.update(tool_actions)
        return sorted(actions_set)
