"""Integration tests for the Go avakill-shim binary.

Tests the full chain: Go shim subprocess → daemon socket → Guard policy
evaluation.  Skipped if the binary is not built.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from avakill.daemon.protocol import EvaluateResponse, serialize_response

# Locate Go shim binary — check build output and PATH
_SHIM_CANDIDATES = [
    Path(__file__).parent.parent / "cmd" / "avakill-shim" / "avakill-shim",
    Path("/usr/local/bin/avakill-shim"),
]

SHIM_BINARY: str | None = None
for _candidate in _SHIM_CANDIDATES:
    if _candidate.is_file() and os.access(_candidate, os.X_OK):
        SHIM_BINARY = str(_candidate)
        break
if SHIM_BINARY is None:
    SHIM_BINARY = shutil.which("avakill-shim")

SKIP_REASON = "avakill-shim binary not built (run: cd cmd/avakill-shim && go build .)"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_upstream():
    """Create a simple echo MCP server script."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False,
        prefix="mock_upstream_",
    ) as script:
        script.write(
            """\
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    if method == "initialize":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"serverInfo": {"name": "mock"}}}
    elif method == "tools/list":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
            {"name": "read_file", "inputSchema": {}},
            {"name": "write_file", "inputSchema": {}},
        ]}}
    elif method == "tools/call":
        name = msg.get("params", {}).get("name", "")
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {
            "content": [{"type": "text", "text": f"executed {name}"}],
        }}
    else:
        resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}
    print(json.dumps(resp), flush=True)
"""
        )
        path = script.name
    yield path
    os.unlink(path)


@pytest.fixture()
def policy_file():
    """Create a policy that allows reads but denies writes."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".yaml",
        delete=False,
        prefix="shim_policy_",
    ) as f:
        f.write(
            """\
version: "1"
rules:
  - name: allow-reads
    action: allow
    tools: ["read_file"]
  - name: deny-writes
    action: deny
    tools: ["write_file"]
    reason: "writes blocked by policy"
  - name: default-allow
    action: allow
    tools: ["*"]
"""
        )
        path = f.name
    yield path
    os.unlink(path)


def _run_shim(args: list[str], stdin_data: str, timeout: int = 10) -> tuple[str, str, int]:
    """Run the shim binary with input and return (stdout, stderr, returncode)."""
    result = subprocess.run(
        [SHIM_BINARY] + args,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def _parse_first_response(stdout: str) -> dict:
    """Parse the first JSON-RPC response from stdout."""
    lines = [line for line in stdout.strip().split("\n") if line.strip()]
    assert len(lines) >= 1, f"expected at least 1 response line, got: {stdout!r}"
    return json.loads(lines[0])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(SHIM_BINARY is None, reason=SKIP_REASON)
class TestShimVersion:
    def test_version_flag(self):
        result = subprocess.run(
            [SHIM_BINARY, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "avakill-shim" in result.stdout


@pytest.mark.skipif(SHIM_BINARY is None, reason=SKIP_REASON)
class TestShimDiagnose:
    def test_diagnose_outputs_json(self):
        result = subprocess.run(
            [SHIM_BINARY, "--diagnose", "--upstream-cmd", "echo"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = json.loads(result.stdout)
        assert "checks" in output
        assert "version" in output
        assert isinstance(output["checks"], list)

    def test_diagnose_no_upstream_fails(self):
        result = subprocess.run(
            [SHIM_BINARY, "--diagnose"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = json.loads(result.stdout)
        assert output["ok"] is False


@pytest.mark.skipif(SHIM_BINARY is None, reason=SKIP_REASON)
class TestShimProxySubprocess:
    """Test the shim with subprocess fallback (--policy flag)."""

    def test_allowed_tool_reaches_upstream(self, mock_upstream, policy_file):
        """tools/call for read_file should reach the mock upstream."""
        request = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 1,
                    "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
                }
            )
            + "\n"
        )

        stdout, stderr, rc = _run_shim(
            [
                "--upstream-cmd",
                "python3",
                "--upstream-args",
                mock_upstream,
                "--policy",
                policy_file,
            ],
            stdin_data=request,
        )

        resp = _parse_first_response(stdout)
        assert resp.get("jsonrpc") == "2.0"
        assert resp.get("id") == 1

    def test_denied_tool_blocked(self, mock_upstream, policy_file):
        """tools/call for write_file should be blocked by policy."""
        request = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 2,
                    "params": {"name": "write_file", "arguments": {"path": "/etc/passwd"}},
                }
            )
            + "\n"
        )

        stdout, stderr, rc = _run_shim(
            [
                "--upstream-cmd",
                "python3",
                "--upstream-args",
                mock_upstream,
                "--policy",
                policy_file,
            ],
            stdin_data=request,
        )

        resp = _parse_first_response(stdout)
        assert resp.get("jsonrpc") == "2.0"
        assert resp.get("id") == 2
        result = resp.get("result", {})
        assert result.get("isError") is True
        content = result.get("content", [])
        assert len(content) >= 1
        assert "AvaKill" in content[0].get("text", "")

    def test_non_tools_call_passes_through(self, mock_upstream, policy_file):
        """Non-tools/call messages should pass through unchanged."""
        request = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "id": 1,
                    "params": {},
                }
            )
            + "\n"
        )

        stdout, stderr, rc = _run_shim(
            [
                "--upstream-cmd",
                "python3",
                "--upstream-args",
                mock_upstream,
                "--policy",
                policy_file,
            ],
            stdin_data=request,
        )

        resp = _parse_first_response(stdout)
        assert resp.get("jsonrpc") == "2.0"
        assert resp.get("id") == 1
        result = resp.get("result", {})
        assert "serverInfo" in result


@pytest.mark.skipif(SHIM_BINARY is None, reason=SKIP_REASON)
class TestShimDaemonIntegration:
    """Test the shim with a mock daemon socket."""

    @staticmethod
    def _start_mock_daemon(
        sock_path: str, decision: str, reason: str = "", policy: str = ""
    ) -> threading.Thread:
        """Start a mock daemon in a thread that responds with a fixed decision."""

        def handler():
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(sock_path)
            server.listen(1)
            server.settimeout(10)
            try:
                conn, _ = server.accept()
                # Read until EOF
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                resp = EvaluateResponse(decision=decision, reason=reason, policy=policy)
                conn.sendall(serialize_response(resp))
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        thread = threading.Thread(target=handler, daemon=True)
        thread.start()
        return thread

    def test_daemon_allow(self, mock_upstream):
        """Shim should forward to upstream when daemon says allow."""
        sock_dir = tempfile.mkdtemp(prefix="ak-", dir="/tmp")
        sock_path = os.path.join(sock_dir, "s.sock")

        thread = self._start_mock_daemon(sock_path, "allow", policy="test-allow")

        try:
            request = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "id": 1,
                        "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
                    }
                )
                + "\n"
            )

            stdout, stderr, rc = _run_shim(
                [
                    "--upstream-cmd",
                    "python3",
                    "--upstream-args",
                    mock_upstream,
                    "--socket",
                    sock_path,
                ],
                stdin_data=request,
            )

            resp = _parse_first_response(stdout)
            assert resp.get("id") == 1
            result = resp.get("result", {})
            assert result.get("isError") is not True
        finally:
            thread.join(timeout=5)
            shutil.rmtree(sock_dir, ignore_errors=True)

    def test_daemon_deny(self, mock_upstream):
        """Shim should return deny response when daemon says deny."""
        sock_dir = tempfile.mkdtemp(prefix="ak-", dir="/tmp")
        sock_path = os.path.join(sock_dir, "s.sock")

        thread = self._start_mock_daemon(
            sock_path,
            "deny",
            reason="blocked by test daemon",
            policy="test-deny",
        )

        try:
            request = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "id": 1,
                        "params": {"name": "write_file", "arguments": {"path": "/etc/shadow"}},
                    }
                )
                + "\n"
            )

            stdout, stderr, rc = _run_shim(
                [
                    "--upstream-cmd",
                    "python3",
                    "--upstream-args",
                    mock_upstream,
                    "--socket",
                    sock_path,
                ],
                stdin_data=request,
            )

            resp = _parse_first_response(stdout)
            assert resp.get("id") == 1
            result = resp.get("result", {})
            assert result.get("isError") is True
            content = result.get("content", [])
            assert "AvaKill" in content[0].get("text", "")
        finally:
            thread.join(timeout=5)
            shutil.rmtree(sock_dir, ignore_errors=True)
