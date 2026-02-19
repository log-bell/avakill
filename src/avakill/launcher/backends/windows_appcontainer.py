"""Windows AppContainer API wrappers via ctypes.

Provides functions for creating/deleting AppContainer profiles,
deriving container SIDs, and modifying DACLs to grant per-directory
access to a containerized process.

All APIs use ctypes against userenv.dll, advapi32.dll, and kernel32.dll.
No external dependencies required.

Reference: https://learn.microsoft.com/en-us/windows/win32/api/userenv/
"""

from __future__ import annotations

import ctypes
import hashlib
import logging
import sys
from typing import Any

logger = logging.getLogger("avakill.launcher.sandbox")

if sys.platform == "win32":
    import ctypes.wintypes

    userenv = ctypes.windll.userenv  # type: ignore[attr-defined]
    advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]


# Win32 constants
DACL_SECURITY_INFORMATION = 0x00000004
GRANT_ACCESS = 1
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03
TRUSTEE_IS_SID = 0
TRUSTEE_IS_WELL_KNOWN_GROUP = 5
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
SE_FILE_OBJECT = 1


def container_name_from_policy(policy_path: str) -> str:
    """Generate a deterministic AppContainer name from a policy path.

    The name must be <= 64 characters and contain only [a-zA-Z0-9.-_].
    Uses SHA-256 hash of the policy path for uniqueness.
    """
    digest = hashlib.sha256(policy_path.encode()).hexdigest()[:16]
    return f"avakill-{digest}"


def create_app_container(name: str) -> Any:
    """Create an AppContainer profile and return its SID.

    If the profile already exists (same name = same SID), returns
    the existing SID. The profile persists across reboots.

    Args:
        name: The moniker for the AppContainer (max 64 chars).

    Returns:
        A PSID pointer to the container's Package SID.

    Raises:
        OSError: If CreateAppContainerProfile fails.
    """
    if sys.platform != "win32":
        raise RuntimeError("AppContainer is only available on Windows")

    sid = ctypes.c_void_p()
    hr = userenv.CreateAppContainerProfile(
        name,
        name,
        name,
        None,
        0,
        ctypes.byref(sid),
    )

    if hr == -2147023436:  # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
        hr2 = userenv.DeriveAppContainerSidFromAppContainerName(
            name,
            ctypes.byref(sid),
        )
        if hr2 != 0:
            raise OSError(f"DeriveAppContainerSidFromAppContainerName failed: {hr2:#x}")
    elif hr != 0:
        raise OSError(f"CreateAppContainerProfile failed: {hr:#x}")

    return sid


def delete_app_container(name: str) -> None:
    """Delete an AppContainer profile."""
    if sys.platform != "win32":
        return
    userenv.DeleteAppContainerProfile(name)


def grant_directory_access(
    container_sid: Any,
    directory: str,
    *,
    read: bool = True,
    write: bool = False,
    execute: bool = False,
) -> None:
    """Modify a directory's DACL to grant access to an AppContainer SID.

    By default, AppContainer processes have zero filesystem access
    outside their package directory. This function adds an ACE granting
    the container's SID access to the specified directory.
    """
    if sys.platform != "win32":
        return

    access_mask = 0
    if read:
        access_mask |= GENERIC_READ
    if write:
        access_mask |= GENERIC_WRITE
    if execute:
        access_mask |= GENERIC_EXECUTE

    _add_ace_to_directory(directory, container_sid, access_mask)


def _add_ace_to_directory(directory: str, sid: Any, access_mask: int) -> None:
    """Low-level DACL manipulation to add an ACE."""
    import ctypes.wintypes

    old_dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        directory,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(old_dacl),
        None,
        ctypes.byref(sd),
    )
    if result != 0:
        logger.warning("GetNamedSecurityInfoW failed for %s: error %d", directory, result)
        return

    try:

        class EXPLICIT_ACCESS_W(ctypes.Structure):
            _fields_ = [
                ("grfAccessPermissions", ctypes.wintypes.DWORD),
                ("grfAccessMode", ctypes.c_int),
                ("grfInheritance", ctypes.wintypes.DWORD),
                ("Trustee_pMultipleTrustee", ctypes.c_void_p),
                ("Trustee_MultipleTrusteeOperation", ctypes.c_int),
                ("Trustee_TrusteeForm", ctypes.c_int),
                ("Trustee_TrusteeType", ctypes.c_int),
                ("Trustee_ptstrName", ctypes.c_void_p),
            ]

        ea = EXPLICIT_ACCESS_W()
        ea.grfAccessPermissions = access_mask
        ea.grfAccessMode = GRANT_ACCESS
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
        ea.Trustee_pMultipleTrustee = None
        ea.Trustee_MultipleTrusteeOperation = 0
        ea.Trustee_TrusteeForm = TRUSTEE_IS_SID
        ea.Trustee_TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP
        ea.Trustee_ptstrName = sid

        new_dacl = ctypes.c_void_p()
        result = advapi32.SetEntriesInAclW(
            1,
            ctypes.byref(ea),
            old_dacl,
            ctypes.byref(new_dacl),
        )
        if result != 0:
            logger.warning("SetEntriesInAclW failed: error %d", result)
            return

        result = advapi32.SetNamedSecurityInfoW(
            directory,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            new_dacl,
            None,
        )
        if result != 0:
            logger.warning("SetNamedSecurityInfoW failed for %s: error %d", directory, result)

        if new_dacl:
            kernel32.LocalFree(new_dacl)
    finally:
        if sd:
            kernel32.LocalFree(sd)
