"""Tests for the C-level audit hooks extension.

All blocking tests run in subprocesses because:
1. C-level audit hooks are irremovable for the interpreter lifetime
2. Once armed, ctypes and gc are blocked globally
3. pytest itself uses gc, so arming in-process would break the test runner
"""

from __future__ import annotations

import subprocess
import sys

import pytest

PYTHON = sys.executable

# Check if the C extension is available (opt-in build via AVAKILL_BUILD_C_EXTENSION=1)
try:
    import avakill._avakill_hooks  # noqa: F401

    _C_EXT_AVAILABLE = True
except ImportError:
    _C_EXT_AVAILABLE = False

requires_c_ext = pytest.mark.skipif(
    not _C_EXT_AVAILABLE,
    reason="C extension not built (set AVAKILL_BUILD_C_EXTENSION=1 to build)",
)


def _run(code: str) -> subprocess.CompletedProcess[str]:
    """Run Python code in a fresh subprocess."""
    return subprocess.run(
        [PYTHON, "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
    )


@requires_c_ext
class TestCHookInstallation:
    def test_is_active_returns_true(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import is_active; assert is_active() is True; print('ok')"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_import_is_idempotent(self) -> None:
        r = _run(
            "import avakill._avakill_hooks; "
            "import avakill._avakill_hooks; "
            "assert avakill._avakill_hooks.is_active() is True; "
            "print('ok')"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_not_armed_by_default(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import is_armed; assert is_armed() is False; print('ok')"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_arm_activates_blocking(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import arm, is_armed; "
            "assert is_armed() is False; "
            "arm(); "
            "assert is_armed() is True; "
            "print('ok')"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout


@requires_c_ext
class TestCHookBlocking:
    """These tests arm the hook then verify blocking works."""

    def test_blocks_ctypes_after_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "try:\n"
            "    import ctypes\n"
            "    print('FAIL: ctypes imported')\n"
            "except RuntimeError as e:\n"
            "    assert 'blocked' in str(e).lower()\n"
            "    print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_blocks_gc_get_objects_after_arm(self) -> None:
        r = _run(
            "import gc\n"
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "try:\n"
            "    gc.get_objects()\n"
            "    print('FAIL')\n"
            "except RuntimeError as e:\n"
            "    assert 'blocked' in str(e).lower()\n"
            "    print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_blocks_gc_get_referrers_after_arm(self) -> None:
        r = _run(
            "import gc\n"
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "obj = [1, 2, 3]\n"
            "try:\n"
            "    gc.get_referrers(obj)\n"
            "    print('FAIL')\n"
            "except RuntimeError as e:\n"
            "    assert 'blocked' in str(e).lower()\n"
            "    print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_blocks_gc_get_referents_after_arm(self) -> None:
        r = _run(
            "import gc\n"
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "obj = [1, 2, 3]\n"
            "try:\n"
            "    gc.get_referents(obj)\n"
            "    print('FAIL')\n"
            "except RuntimeError as e:\n"
            "    assert 'blocked' in str(e).lower()\n"
            "    print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_ctypes_works_before_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import is_active\n"
            "assert is_active()\n"
            "import ctypes  # should work before arm()\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_gc_works_before_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import is_active\n"
            "assert is_active()\n"
            "import gc\n"
            "gc.get_objects()  # should work before arm()\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout


@requires_c_ext
class TestCHookAllowsNormal:
    def test_allows_normal_imports_after_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import arm\narm()\nimport json, os, hashlib\nprint('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_allows_file_operations_after_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "import tempfile, os\n"
            "fd, path = tempfile.mkstemp()\n"
            "os.write(fd, b'hello')\n"
            "os.close(fd)\n"
            "with open(path) as f: data = f.read()\n"
            "assert data == 'hello'\n"
            "os.unlink(path)\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_allows_subprocess_after_arm(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "import subprocess\n"
            "r = subprocess.run(['echo', 'hi'], capture_output=True, text=True)\n"
            "assert r.returncode == 0\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout


@requires_c_ext
class TestRemoteExecDisabled:
    def test_python_disable_remote_debug_set(self) -> None:
        r = _run(
            "from avakill._avakill_hooks import is_active\n"
            "import os\n"
            "val = os.environ.get('PYTHON_DISABLE_REMOTE_DEBUG')\n"
            "assert val == '1', f'Expected 1, got {val}'\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout


class TestGracefulDegradation:
    def test_python_hooks_work_without_c(self) -> None:
        """AuditHookManager works even without arming C hooks."""
        from avakill.core.audit_hooks import AuditHookManager

        mgr = AuditHookManager(protected_paths=set())
        assert mgr.is_installed is False


@requires_c_ext
class TestAuditHooksIntegration:
    def test_c_hooks_detected(self) -> None:
        r = _run(
            "from avakill.core.audit_hooks import c_hooks_available\n"
            "assert c_hooks_available() is True\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout

    def test_arm_called_on_install(self) -> None:
        r = _run(
            "from avakill.core.audit_hooks import AuditHookManager, c_hooks_available\n"
            "assert c_hooks_available()\n"
            "mgr = AuditHookManager(protected_paths=set())\n"
            "mgr.install()\n"
            "from avakill._avakill_hooks import is_armed\n"
            "assert is_armed() is True\n"
            "print('ok')\n"
        )
        assert r.returncode == 0
        assert "ok" in r.stdout


@requires_c_ext
class TestGuardHardenedStatus:
    def test_guard_reports_hardened(self) -> None:
        r = _run(
            "import tempfile, os\n"
            "from avakill._avakill_hooks import arm\n"
            "arm()\n"
            "from avakill.core.integrity import PolicyIntegrity\n"
            "key = bytes.fromhex('aa' * 32)\n"
            "td = tempfile.mkdtemp()\n"
            "pf = os.path.join(td, 'avakill.yaml')\n"
            "with open(pf, 'w') as f:\n"
            "    f.write(\"version: '1.0'\\ndefault_action: deny\\n\"\n"
            '            "policies:\\n  - name: t\\n    tools: [x]\\n    action: allow\\n")\n'
            "PolicyIntegrity.sign_file(pf, key)\n"
            "from avakill.core.engine import Guard\n"
            "g = Guard(policy=pf, signing_key=key, self_protection=False)\n"
            "assert g.policy_status == 'hardened', f'got {g.policy_status}'\n"
            "print('ok')\n"
        )
        assert r.returncode == 0, f"stderr: {r.stderr}"
        assert "ok" in r.stdout


class TestCheckHardeningCLI:
    def test_shows_c_hooks_status(self) -> None:
        r = _run(
            "import tempfile, os\n"
            "from click.testing import CliRunner\n"
            "from avakill.cli.main import cli\n"
            "td = tempfile.mkdtemp()\n"
            "pf = os.path.join(td, 'avakill.yaml')\n"
            "with open(pf, 'w') as f:\n"
            "    f.write(\"version: '1.0'\\ndefault_action: deny\\n\"\n"
            '            "policies:\\n  - name: t\\n    tools: [x]\\n    action: allow\\n")\n'
            "runner = CliRunner()\n"
            "result = runner.invoke(cli, ['check-hardening', pf])\n"
            "assert result.exit_code == 0\n"
            "assert 'C-Level Hooks' in result.output\n"
            "print('ok')\n"
        )
        assert r.returncode == 0, f"stderr: {r.stderr}"
        assert "ok" in r.stdout
