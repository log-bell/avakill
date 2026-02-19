"""Python audit hooks for detecting writes to protected files.

These hooks are Tier 3 (detection, not enforcement). They catch accidental
modification and force adversarial agents to use non-obvious techniques.
They are NOT a sandbox -- Python's own documentation warns that audit hooks
can be bypassed by malicious code.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Try to import C-level audit hooks (compiled C extension)
_c_hooks_active = False
try:
    from avakill._avakill_hooks import arm as _c_arm  # type: ignore[import-not-found]
    from avakill._avakill_hooks import is_active as _c_is_active  # type: ignore[import-not-found]

    _c_hooks_active = _c_is_active()
    logger.info("C-level audit hooks available")
except ImportError:
    _c_arm = None
    logger.info(
        "C-level audit hooks not available -- install avakill[hardened] for maximum protection"
    )


def c_hooks_available() -> bool:
    """Return True if C-level audit hooks are installed."""
    return _c_hooks_active


class AuditHookManager:
    """Manages Python audit hooks for protecting AvaKill files.

    Installs a ``sys.addaudithook()`` callback that blocks write/append
    opens to protected paths and logs security-relevant events.

    Warning:
        Python audit hooks are bypassable via ctypes or gc introspection.
        This is a detection tripwire, not an enforcement boundary.
    """

    def __init__(
        self,
        protected_paths: set[str],
        event_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the audit hook manager.

        Args:
            protected_paths: Set of absolute file paths to protect from writes.
            event_callback: Optional callback(event_name, detail) called on violations.
        """
        self._protected_paths = {os.path.realpath(p) for p in protected_paths}
        self._event_callback = event_callback
        self._installed = False

    @property
    def is_installed(self) -> bool:
        """Whether the audit hook has been installed."""
        return self._installed

    def install(self) -> None:
        """Install the audit hook via sys.addaudithook().

        This is irreversible for the lifetime of the interpreter -- Python
        provides no mechanism to remove audit hooks.
        """
        if self._installed:
            return

        # Capture references for the closure
        protected = self._protected_paths
        callback = self._event_callback

        def _hook(event: str, args: tuple[Any, ...]) -> None:
            if event == "open":
                _handle_open(event, args, protected, callback)

        sys.addaudithook(_hook)

        # Arm C-level hooks now that initialization is complete
        if _c_arm is not None:
            _c_arm()
            logger.info("C-level audit hooks armed -- ctypes and gc introspection blocked")

        self._installed = True
        logger.info("Audit hooks installed, protecting %d paths", len(self._protected_paths))

    def add_protected_path(self, path: str) -> None:
        """Add a path to the protected set (takes effect immediately)."""
        self._protected_paths.add(os.path.realpath(path))


def _handle_open(
    event: str,
    args: tuple[Any, ...],
    protected: set[str],
    callback: Callable[[str, str], None] | None,
) -> None:
    """Handle 'open' audit events."""
    if len(args) < 2:
        return
    path_arg = str(args[0])
    mode = str(args[1]) if len(args) > 1 else "r"

    # Only block write/append modes
    if not any(m in mode for m in ("w", "a", "x")):
        return

    try:
        real = os.path.realpath(path_arg)
    except (OSError, ValueError):
        return

    if real in protected:
        detail = f"blocked write to protected file: {real} (mode={mode})"
        logger.warning("Audit hook: %s", detail)
        if callback is not None:
            callback(event, detail)
        raise PermissionError(f"AvaKill audit hook: {detail}")
