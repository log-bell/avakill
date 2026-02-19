"""Tests for the AvaKill Python audit hooks.

IMPORTANT: Python audit hooks are global and irreversible (sys.addaudithook
cannot be undone). Each test that installs a hook must use unique protected
paths to avoid interference. Tests that install hooks run in-process but
with isolated path sets.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from avakill.core.audit_hooks import AuditHookManager


class TestAuditHookManager:
    def test_install_registers_hook(self, monkeypatch) -> None:
        # Prevent C-level hooks from being armed (irreversible, blocks ctypes)
        monkeypatch.setattr("avakill.core.audit_hooks._c_arm", None)
        mgr = AuditHookManager(protected_paths=set())
        assert mgr.is_installed is False
        mgr.install()
        assert mgr.is_installed is True

    def test_blocks_write_to_protected_path(self, tmp_path: Path) -> None:
        """Run in subprocess to avoid audit hook pollution."""
        protected = tmp_path / "avakill_write_block.yaml"
        protected.write_text("test")
        abs_path = str(protected.resolve())

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"""
import sys
from avakill.core.audit_hooks import AuditHookManager

mgr = AuditHookManager(protected_paths={{"{abs_path}"}})
mgr.install()
try:
    open("{abs_path}", "w")
    print("NOT_BLOCKED")
except PermissionError as e:
    if "protected" in str(e).lower():
        print("BLOCKED")
    else:
        print(f"WRONG_ERROR: {{e}}")
""",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "BLOCKED" in result.stdout, f"stdout: {result.stdout}, stderr: {result.stderr}"

    def test_allows_read_of_protected_path(self, tmp_path: Path) -> None:
        """Run in subprocess to avoid audit hook pollution."""
        protected = tmp_path / "avakill_read_allow.yaml"
        protected.write_text("safe to read")
        abs_path = str(protected.resolve())

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"""
from avakill.core.audit_hooks import AuditHookManager

mgr = AuditHookManager(protected_paths={{"{abs_path}"}})
mgr.install()
with open("{abs_path}") as f:
    content = f.read()
if content == "safe to read":
    print("READ_OK")
else:
    print(f"WRONG_CONTENT: {{content}}")
""",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "READ_OK" in result.stdout, f"stdout: {result.stdout}, stderr: {result.stderr}"

    def test_allows_write_to_unprotected_path(self, tmp_path: Path) -> None:
        """Run in subprocess to avoid audit hook pollution."""
        protected = tmp_path / "avakill_unprotected.yaml"
        protected.write_text("protected")
        unprotected = tmp_path / "other.txt"
        abs_protected = str(protected.resolve())
        abs_unprotected = str(unprotected)

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"""
from avakill.core.audit_hooks import AuditHookManager

mgr = AuditHookManager(protected_paths={{"{abs_protected}"}})
mgr.install()
with open("{abs_unprotected}", "w") as f:
    f.write("fine")
with open("{abs_unprotected}") as f:
    content = f.read()
if content == "fine":
    print("WRITE_OK")
else:
    print(f"WRONG_CONTENT: {{content}}")
""",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "WRITE_OK" in result.stdout, f"stdout: {result.stdout}, stderr: {result.stderr}"

    def test_event_callback_called_on_violation(self, tmp_path: Path) -> None:
        """Run in subprocess to avoid audit hook pollution."""
        protected = tmp_path / "avakill_callback.yaml"
        protected.write_text("test")
        abs_path = str(protected.resolve())

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"""
import sys

events = []
def callback(event_name, detail):
    events.append((event_name, detail))

from avakill.core.audit_hooks import AuditHookManager
mgr = AuditHookManager(
    protected_paths={{"{abs_path}"}},
    event_callback=callback,
)
mgr.install()

try:
    open("{abs_path}", "w")
except PermissionError:
    pass

if len(events) == 1:
    name, detail = events[0]
    if name == "open" and "{abs_path}" in detail:
        print("CALLBACK_OK")
    else:
        print(f"WRONG_EVENT: {{name}} {{detail}}")
else:
    print(f"WRONG_COUNT: {{len(events)}}")
""",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "CALLBACK_OK" in result.stdout, f"stdout: {result.stdout}, stderr: {result.stderr}"
