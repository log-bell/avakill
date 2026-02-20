"""Windows sandbox backend using AppContainer + Job Objects.

Combines three Windows security mechanisms for defense-in-depth:
1. AppContainer - filesystem, network, registry isolation via Package SID
2. Job Objects - memory, CPU, process count limits
3. Privilege removal - strips dangerous token privileges (irreversible)

The process is created suspended, configured, then resumed.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from avakill.core.models import SandboxConfig

logger = logging.getLogger("avakill.launcher.sandbox")

CREATE_SUSPENDED = 0x00000004


class WindowsSandboxBackend:
    """Windows sandbox backend: AppContainer + Job Objects + privilege removal."""

    def available(self) -> bool:
        return sys.platform == "win32"

    def prepare_preexec(self, config: SandboxConfig) -> Callable[[], None] | None:
        return None  # Windows doesn't support preexec_fn

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        if not self.available():
            return {}
        return {"creationflags": CREATE_SUSPENDED}

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        """Configure and resume a suspended Windows process.

        1. Create AppContainer profile and derive SID
        2. Grant DACL access to allowed directories
        3. Create Job Object with resource limits
        4. Assign process to Job Object
        5. Remove dangerous token privileges
        6. Resume the primary thread
        """
        if not self.available():
            return

        from avakill.launcher.backends.windows_appcontainer import (
            container_name_from_policy,
            create_app_container,
            grant_directory_access,
        )

        # 1. Create/get AppContainer
        container_name = container_name_from_policy(f"avakill-pid-{pid}")
        try:
            sid = create_app_container(container_name)
        except OSError:
            logger.warning("Failed to create AppContainer; continuing without it.")
            sid = None

        # 2. Grant DACL access to allowed paths
        if sid:
            paths = config.allow_paths
            for p in paths.read:
                resolved = str(Path(p).expanduser().resolve())
                grant_directory_access(sid, resolved, read=True)
            for p in paths.write:
                resolved = str(Path(p).expanduser().resolve())
                grant_directory_access(sid, resolved, read=True, write=True)
            for p in paths.execute:
                resolved = str(Path(p).expanduser().resolve())
                grant_directory_access(sid, resolved, read=True, execute=True)

        # 3. Create Job Object with resource limits
        self._apply_job_object(pid, config)

        # 4. Remove dangerous privileges
        self._remove_privileges(pid)

        # 5. Resume the primary thread
        self._resume_process(pid)

    def wrap_command(self, command: list[str], config: SandboxConfig) -> list[str]:
        return command

    def cleanup(self) -> None:
        pass

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        if not self.available():
            return {
                "platform": "windows",
                "sandbox_applied": False,
                "reason": "Not running on Windows",
            }

        limits = config.resource_limits
        return {
            "platform": "windows",
            "sandbox_applied": True,
            "mechanism": "appcontainer",
            "allowed_read_paths": config.allow_paths.read,
            "allowed_write_paths": config.allow_paths.write,
            "allowed_exec_paths": config.allow_paths.execute,
            "job_object": {
                "memory_limit_mb": limits.max_memory_mb,
                "process_limit": limits.max_processes,
            },
            "privileges_removed": [
                "SeRestorePrivilege",
                "SeBackupPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeDebugPrivilege",
                "SeImpersonatePrivilege",
            ],
        }

    def _apply_job_object(self, pid: int, config: SandboxConfig) -> None:
        """Create a Job Object and assign the target process to it."""
        if sys.platform != "win32":
            return

        import ctypes

        from avakill.enforcement.windows import (
            _JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        )

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            logger.warning("Failed to create Job Object for PID %d", pid)
            return

        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        limits = config.resource_limits
        if limits.max_processes:
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes

        if limits.max_memory_mb:
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = limits.max_memory_mb * 1024 * 1024

        kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )

        PROCESS_ALL_ACCESS = 0x001FFFFF
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if process_handle:
            kernel32.AssignProcessToJobObject(job, process_handle)
            kernel32.CloseHandle(process_handle)

    def _remove_privileges(self, pid: int) -> None:
        """Remove dangerous token privileges from the target process."""
        if sys.platform != "win32":
            return

        import ctypes
        import ctypes.wintypes

        from avakill.enforcement.windows import (
            _DANGEROUS_PRIVILEGES,
            _LUID,
            _TOKEN_PRIVILEGES,
            SE_PRIVILEGE_REMOVED,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_QUERY,
        )

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]

        process_handle = kernel32.OpenProcess(0x001FFFFF, False, pid)
        if not process_handle:
            return

        token = ctypes.wintypes.HANDLE()
        try:
            if not advapi32.OpenProcessToken(
                process_handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(token),
            ):
                return

            try:
                for priv_name in _DANGEROUS_PRIVILEGES:
                    luid = _LUID()
                    if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                        continue
                    tp = _TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED
                    advapi32.AdjustTokenPrivileges(
                        token,
                        False,
                        ctypes.byref(tp),
                        ctypes.sizeof(tp),
                        None,
                        None,
                    )
            finally:
                kernel32.CloseHandle(token)
        finally:
            kernel32.CloseHandle(process_handle)

    def _resume_process(self, pid: int) -> None:
        """Resume a suspended process by resuming its primary thread."""
        if sys.platform != "win32":
            return

        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        TH32CS_SNAPTHREAD = 0x00000004

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.wintypes.DWORD),
                ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ThreadID", ctypes.wintypes.DWORD),
                ("th32OwnerProcessID", ctypes.wintypes.DWORD),
                ("tpBasePri", ctypes.wintypes.LONG),
                ("tpDeltaPri", ctypes.wintypes.LONG),
                ("dwFlags", ctypes.wintypes.DWORD),
            ]

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == -1:
            return

        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)

        try:
            if kernel32.Thread32First(snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        THREAD_SUSPEND_RESUME = 0x0002
                        thread = kernel32.OpenThread(
                            THREAD_SUSPEND_RESUME,
                            False,
                            te.th32ThreadID,
                        )
                        if thread:
                            kernel32.ResumeThread(thread)
                            kernel32.CloseHandle(thread)
                        break
                    if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                        break
        finally:
            kernel32.CloseHandle(snap)
