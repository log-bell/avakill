# OpenAI Codex CLI Hook Adapter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an OpenAI Codex CLI hook adapter with dual-mode stdin parsing, exec policy `.rules` generation, and full test coverage.

**Architecture:** New `OpenAICodexAdapter(HookAdapter)` class supports two stdin formats (nested Codex `HookPayload` and flat generic) with auto-detection. Response uses JSON on stdout + exit codes. Installer detects Codex CLI, prints upstream-pending message, and generates `~/.codex/rules/avakill.rules` for immediate shell protection.

**Tech Stack:** Python 3.10+, Pydantic v2, Click CLI, pytest

---

### Task 1: Adapter Module — Tests for Nested Format Parsing

**Files:**
- Create: `tests/test_hooks_openai_codex.py`

**Step 1: Write the failing tests for nested (Codex HookPayload) format parsing**

```python
"""Tests for the OpenAI Codex CLI hook adapter."""

from __future__ import annotations

import json

import pytest

from avakill.daemon.protocol import EvaluateResponse
from avakill.hooks.openai_codex import OpenAICodexAdapter


class TestOpenAICodexParseStdinNested:
    """Test parsing Codex nested HookPayload format."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_parse_shell_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/home/user/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_abc",
                    "tool_name": "shell",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "local_shell",
                        "params": {
                            "command": ["rm", "-rf", "/"],
                            "workdir": "/tmp",
                        },
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "shell"
        assert req.args["command"] == "rm -rf /"
        assert req.args["workdir"] == "/tmp"
        assert req.agent == "openai-codex"

    def test_parse_apply_patch_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/home/user/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_def",
                    "tool_name": "apply_patch",
                    "tool_kind": "custom",
                    "tool_input": {
                        "input_type": "custom",
                        "input": "*** Begin Patch\n--- a/foo.py\n+++ b/foo.py\n",
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "apply_patch"
        assert "Begin Patch" in req.args["input"]

    def test_parse_mcp_tool(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/home/user/project",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_ghi",
                    "tool_name": "memory__store",
                    "tool_kind": "mcp",
                    "tool_input": {
                        "input_type": "mcp",
                        "server": "memory",
                        "tool": "store",
                        "arguments": '{"key": "value"}',
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "memory__store"
        assert req.args["mcp_server"] == "memory"
        assert req.args["mcp_tool"] == "store"

    def test_parse_preserves_session_id(self) -> None:
        raw = json.dumps(
            {
                "session_id": "abc-123",
                "cwd": "/tmp",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_1",
                    "tool_name": "shell",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "local_shell",
                        "params": {"command": ["echo", "hi"]},
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "abc-123"
        assert req.context["cwd"] == "/tmp"

    def test_parse_preserves_call_id(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/tmp",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_xyz",
                    "tool_name": "read_file",
                    "tool_kind": "function",
                    "tool_input": {"input_type": "custom", "input": "/etc/passwd"},
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["call_id"] == "call_xyz"

    def test_parse_unknown_input_type_passes_through(self) -> None:
        raw = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/tmp",
                "hook_event": {
                    "event_type": "before_tool_use",
                    "call_id": "call_1",
                    "tool_name": "new_tool",
                    "tool_kind": "function",
                    "tool_input": {
                        "input_type": "future_type",
                        "some_field": "some_value",
                    },
                },
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "new_tool"
        assert req.args["some_field"] == "some_value"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            self.adapter.parse_stdin("not json{{{")
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexParseStdinNested -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'avakill.hooks.openai_codex'`

**Step 3: Write minimal adapter implementation for nested parsing**

Create `src/avakill/hooks/openai_codex.py`:

```python
"""OpenAI Codex CLI hook adapter.

Translates Codex's tool call payloads into AvaKill's wire protocol.
Supports two stdin formats with auto-detection:

1. Nested HookPayload format (anticipated before_tool_use event)::

    {
      "session_id": "...",
      "cwd": "/path",
      "hook_event": {
        "event_type": "before_tool_use",
        "call_id": "call_xxx",
        "tool_name": "shell",
        "tool_kind": "function",
        "tool_input": {
          "input_type": "local_shell",
          "params": {"command": ["rm", "-rf", "/"], "workdir": "/tmp"}
        }
      }
    }

2. Flat format (generic)::

    {
      "tool_name": "shell",
      "tool_input": {"command": "rm -rf /"},
      "session_id": "..."
    }

Response format (JSON on stdout)::

    Allow:  {"decision": "proceed"}           exit 0
    Deny:   {"decision": "block", "message": "..."}  exit 1

Note: Codex CLI does not yet support pre-execution hooks upstream.
This adapter is anticipatory — it will activate when upstream support
ships.  See https://github.com/openai/codex/issues/2109
"""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


def _extract_args_from_tool_input(tool_input: dict[str, object]) -> dict[str, object]:
    """Normalize Codex's typed tool_input variants into a flat args dict."""
    input_type = tool_input.get("input_type", "")

    if input_type == "local_shell":
        params = tool_input.get("params", {})
        if not isinstance(params, dict):
            params = {}
        args: dict[str, object] = {}
        command = params.get("command")
        if isinstance(command, list):
            args["command"] = " ".join(str(c) for c in command)
        elif isinstance(command, str):
            args["command"] = command
        if "workdir" in params:
            args["workdir"] = params["workdir"]
        return args

    if input_type == "custom":
        args = {}
        if "input" in tool_input:
            args["input"] = tool_input["input"]
        return args

    if input_type == "mcp":
        args = {}
        if "server" in tool_input:
            args["mcp_server"] = tool_input["server"]
        if "tool" in tool_input:
            args["mcp_tool"] = tool_input["tool"]
        if "arguments" in tool_input:
            args["arguments"] = tool_input["arguments"]
        return args

    # Unknown input_type — pass through all fields except input_type.
    return {k: v for k, v in tool_input.items() if k != "input_type"}


@register_adapter
class OpenAICodexAdapter(HookAdapter):
    """Hook adapter for OpenAI Codex CLI."""

    agent_name = "openai-codex"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Codex tool call payload (nested or flat format)."""
        data = json.loads(raw)

        if "hook_event" in data:
            return self._parse_nested(data)
        return self._parse_flat(data)

    def _parse_nested(self, data: dict[str, object]) -> EvaluateRequest:
        """Parse the nested Codex HookPayload format."""
        hook_event = data["hook_event"]
        if not isinstance(hook_event, dict):
            raise ValueError("hook_event must be a dict")

        tool = str(hook_event.get("tool_name", ""))
        event_type = str(hook_event.get("event_type", "before_tool_use"))

        tool_input = hook_event.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}
        args = _extract_args_from_tool_input(tool_input)

        context: dict[str, object] = {}
        if "session_id" in data:
            context["session_id"] = data["session_id"]
        if "cwd" in data:
            context["cwd"] = data["cwd"]
        if "call_id" in hook_event:
            context["call_id"] = hook_event["call_id"]
        if "tool_kind" in hook_event:
            context["tool_kind"] = hook_event["tool_kind"]

        return EvaluateRequest(
            agent=self.agent_name,
            event=event_type,
            tool=tool,
            args=args,
            context=context,
        )

    def _parse_flat(self, data: dict[str, object]) -> EvaluateRequest:
        """Parse the flat generic format."""
        tool = str(data.get("tool_name", ""))
        args = data.get("tool_input", {})

        context: dict[str, object] = {}
        for key in ("session_id", "cwd", "call_id"):
            if key in data:
                context[key] = data[key]

        return EvaluateRequest(
            agent=self.agent_name,
            event="before_tool_use",
            tool=tool,
            args=args if isinstance(args, dict) else {},
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Codex CLI.

        - Allow: ``{"decision": "proceed"}``, exit 0.
        - Deny: ``{"decision": "block", "message": "..."}``, exit 1.
        - Require approval: ``{"decision": "block", "message": "..."}``, exit 1.
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy:
                reason = f"{reason} [{response.policy}]"
            reason = f"{reason}. Run `avakill fix` for recovery steps."
            payload = {"decision": "block", "message": reason}
            return json.dumps(payload), 1

        if response.decision == "require_approval":
            reason = response.reason or "Requires human approval"
            if response.policy:
                reason = f"{reason} [{response.policy}]"
            payload = {"decision": "block", "message": f"Requires approval: {reason}"}
            return json.dumps(payload), 1

        # Allow.
        payload = {"decision": "proceed"}
        return json.dumps(payload), 0


def main() -> None:
    """Entry point for the ``avakill-hook-openai-codex`` console script."""
    OpenAICodexAdapter().run()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexParseStdinNested -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add tests/test_hooks_openai_codex.py src/avakill/hooks/openai_codex.py
git commit -m "feat: add OpenAI Codex CLI adapter with nested format parsing"
```

---

### Task 2: Adapter Module — Tests for Flat Format Parsing

**Files:**
- Modify: `tests/test_hooks_openai_codex.py`

**Step 1: Write the failing tests for flat format parsing**

Append to `tests/test_hooks_openai_codex.py`:

```python
class TestOpenAICodexParseStdinFlat:
    """Test parsing the flat generic format."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_parse_flat_shell_tool(self) -> None:
        raw = json.dumps(
            {
                "tool_name": "shell",
                "tool_input": {"command": "ls -la"},
                "session_id": "s1",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "shell"
        assert req.args == {"command": "ls -la"}
        assert req.agent == "openai-codex"
        assert req.event == "before_tool_use"

    def test_parse_flat_with_no_tool_input(self) -> None:
        raw = json.dumps({"tool_name": "read_file", "session_id": "s1"})
        req = self.adapter.parse_stdin(raw)
        assert req.tool == "read_file"
        assert req.args == {}

    def test_parse_flat_preserves_context(self) -> None:
        raw = json.dumps(
            {
                "tool_name": "shell",
                "tool_input": {"command": "echo hi"},
                "session_id": "abc-123",
                "cwd": "/home/user",
            }
        )
        req = self.adapter.parse_stdin(raw)
        assert req.context["session_id"] == "abc-123"
        assert req.context["cwd"] == "/home/user"
```

**Step 2: Run tests to verify they pass**

The flat format parsing is already implemented. Run:
`pytest tests/test_hooks_openai_codex.py::TestOpenAICodexParseStdinFlat -v`
Expected: All 3 tests PASS

**Step 3: Commit**

```bash
git add tests/test_hooks_openai_codex.py
git commit -m "test: add flat format parsing tests for Codex adapter"
```

---

### Task 3: Adapter Module — Tests for Response Formatting

**Files:**
- Modify: `tests/test_hooks_openai_codex.py`

**Step 1: Write the tests for format_response**

Append to `tests/test_hooks_openai_codex.py`:

```python
class TestOpenAICodexFormatResponse:
    """Test formatting responses for Codex CLI."""

    def setup_method(self) -> None:
        self.adapter = OpenAICodexAdapter()

    def test_allow_returns_proceed(self) -> None:
        resp = EvaluateResponse(decision="allow")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "proceed"
        assert exit_code == 0

    def test_deny_returns_block_json(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "block"
        assert "blocked" in parsed["message"]

    def test_deny_includes_reason_and_policy(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="dangerous command", policy="safety")
        stdout, _ = self.adapter.format_response(resp)
        parsed = json.loads(stdout)  # type: ignore[arg-type]
        assert "dangerous command" in parsed["message"]
        assert "safety" in parsed["message"]

    def test_deny_exit_code_is_1(self) -> None:
        resp = EvaluateResponse(decision="deny", reason="blocked")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 1

    def test_allow_exit_code_is_0(self) -> None:
        resp = EvaluateResponse(decision="allow")
        _, exit_code = self.adapter.format_response(resp)
        assert exit_code == 0

    def test_require_approval_returns_block(self) -> None:
        resp = EvaluateResponse(decision="require_approval", reason="needs review")
        stdout, exit_code = self.adapter.format_response(resp)
        assert stdout is not None
        parsed = json.loads(stdout)
        assert parsed["decision"] == "block"
        assert "approval" in parsed["message"].lower()
        assert exit_code == 1
```

**Step 2: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexFormatResponse -v`
Expected: All 6 tests PASS

**Step 3: Commit**

```bash
git add tests/test_hooks_openai_codex.py
git commit -m "test: add response formatting tests for Codex adapter"
```

---

### Task 4: Hook Registry and Entry Point

**Files:**
- Modify: `src/avakill/hooks/__init__.py:40-45` — add import
- Modify: `pyproject.toml:87-92` — add entry point

**Step 1: Write a test verifying registry integration**

Append to `tests/test_hooks_openai_codex.py`:

```python
class TestOpenAICodexRegistration:
    """Test adapter registration in the hook registry."""

    def test_adapter_registered_in_registry(self) -> None:
        from avakill.hooks import get_adapter

        adapter_cls = get_adapter("openai-codex")
        assert adapter_cls is OpenAICodexAdapter

    def test_adapter_agent_name(self) -> None:
        adapter = OpenAICodexAdapter()
        assert adapter.agent_name == "openai-codex"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexRegistration -v`
Expected: FAIL — `KeyError: "unknown agent: 'openai-codex'"` (not imported in `_import_all()`)

**Step 3: Add import to `_import_all()` in `src/avakill/hooks/__init__.py`**

Add this line after the windsurf import (line 45):

```python
    import avakill.hooks.openai_codex as _oc  # noqa: F811, F401
```

**Step 4: Add entry point to `pyproject.toml`**

Add after line 92 (`avakill-hook-windsurf`):

```toml
avakill-hook-openai-codex = "avakill.hooks.openai_codex:main"
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexRegistration -v`
Expected: All 2 tests PASS

**Step 6: Commit**

```bash
git add src/avakill/hooks/__init__.py pyproject.toml tests/test_hooks_openai_codex.py
git commit -m "feat: register Codex adapter in hook registry and add entry point"
```

---

### Task 5: Tool Normalization Mappings

**Files:**
- Modify: `src/avakill/core/normalization.py:14-43` — add openai-codex entry

**Step 1: Write the failing test**

Create at end of `tests/test_hooks_openai_codex.py`:

```python
class TestOpenAICodexNormalization:
    """Test tool name normalization for Codex tools."""

    def test_shell_normalizes_to_shell_execute(self) -> None:
        from avakill.core.normalization import normalize_tool_name

        assert normalize_tool_name("shell", "openai-codex") == "shell_execute"

    def test_apply_patch_normalizes_to_file_write(self) -> None:
        from avakill.core.normalization import normalize_tool_name

        assert normalize_tool_name("apply_patch", "openai-codex") == "file_write"

    def test_read_file_normalizes_to_file_read(self) -> None:
        from avakill.core.normalization import normalize_tool_name

        assert normalize_tool_name("read_file", "openai-codex") == "file_read"

    def test_unknown_tool_passes_through(self) -> None:
        from avakill.core.normalization import normalize_tool_name

        assert normalize_tool_name("new_future_tool", "openai-codex") == "new_future_tool"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexNormalization -v`
Expected: FAIL — `AssertionError: assert 'shell' == 'shell_execute'`

**Step 3: Add mappings to `src/avakill/core/normalization.py`**

Add after the `"windsurf"` entry (line 42) in `AGENT_TOOL_MAP`:

```python
    "openai-codex": {
        "shell": "shell_execute",
        "shell_command": "shell_execute",
        "local_shell": "shell_execute",
        "exec_command": "shell_execute",
        "apply_patch": "file_write",
        "read_file": "file_read",
        "list_dir": "file_list",
        "grep_files": "content_search",
    },
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexNormalization -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/avakill/core/normalization.py tests/test_hooks_openai_codex.py
git commit -m "feat: add Codex tool name normalization mappings"
```

---

### Task 6: Installer — Agent Detection

**Files:**
- Modify: `src/avakill/hooks/installer.py:35-59` — add detector

**Step 1: Write the failing test**

Append to `tests/test_hooks_openai_codex.py`:

```python
from pathlib import Path


class TestOpenAICodexDetection:
    """Test Codex CLI agent detection."""

    def test_detect_codex_by_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        from avakill.hooks.installer import detect_agents

        detected = detect_agents()
        assert "openai-codex" in detected

    def test_detect_codex_by_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        import shutil

        original_which = shutil.which

        def mock_which(name: str) -> str | None:
            if name == "codex":
                return "/usr/local/bin/codex"
            return original_which(name)

        monkeypatch.setattr(shutil, "which", mock_which)
        from avakill.hooks.installer import detect_agents

        detected = detect_agents()
        assert "openai-codex" in detected
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexDetection -v`
Expected: FAIL — `assert 'openai-codex' in detected`

**Step 3: Add detector to `src/avakill/hooks/installer.py`**

Add to `AGENT_DETECTORS` dict (after the `"swe-agent"` entry, around line 58):

```python
    "openai-codex": lambda: (
        Path.home().joinpath(".codex").is_dir() or shutil.which("codex") is not None
    ),
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexDetection -v`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add src/avakill/hooks/installer.py tests/test_hooks_openai_codex.py
git commit -m "feat: add Codex CLI agent detection"
```

---

### Task 7: Installer — Hook Install with Rules Generation

**Files:**
- Modify: `src/avakill/hooks/installer.py` — add `_AGENT_CONFIG` entry, handle pending upstream
- Modify: `src/avakill/hooks/openai_codex.py` — add `generate_codex_rules()` function

**Step 1: Write the failing tests**

Append to `tests/test_hooks_openai_codex.py`:

```python
class TestOpenAICodexInstaller:
    """Test hook installation for Codex CLI."""

    def test_install_creates_config_with_pending_flag(self, tmp_path: Path) -> None:
        from avakill.hooks.installer import install_hook

        config_path = tmp_path / "config.toml"
        result = install_hook("openai-codex", config_path=config_path)
        assert isinstance(result, HookInstallResult)
        # Should have a warning about pending upstream support
        assert any("upstream" in w.lower() or "not yet" in w.lower() for w in result.warnings)


class TestCodexRulesGeneration:
    """Test exec policy .rules file generation."""

    def test_generates_deny_prefix_rules(self, tmp_path: Path) -> None:
        from avakill.hooks.openai_codex import generate_codex_rules

        policy_path = tmp_path / "avakill.yaml"
        policy_path.write_text(
            """
version: "1.0"
default_action: allow
policies:
  - name: block-rm
    tools: ["shell*"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf"]
"""
        )
        output_path = tmp_path / "avakill.rules"
        generate_codex_rules(policy_path, output_path)

        content = output_path.read_text()
        assert "prefix_rule" in content
        assert "rm" in content
        assert "forbidden" in content

    def test_generates_allow_prefix_rules(self, tmp_path: Path) -> None:
        from avakill.hooks.openai_codex import generate_codex_rules

        policy_path = tmp_path / "avakill.yaml"
        policy_path.write_text(
            """
version: "1.0"
default_action: deny
policies:
  - name: safe-commands
    tools: ["shell*"]
    action: allow
    conditions:
      command_allowlist: [git, ls, echo]
"""
        )
        output_path = tmp_path / "avakill.rules"
        generate_codex_rules(policy_path, output_path)

        content = output_path.read_text()
        assert 'pattern = ["git"]' in content
        assert 'pattern = ["ls"]' in content
        assert 'decision = "allow"' in content

    def test_skips_non_shell_rules(self, tmp_path: Path) -> None:
        from avakill.hooks.openai_codex import generate_codex_rules

        policy_path = tmp_path / "avakill.yaml"
        policy_path.write_text(
            """
version: "1.0"
default_action: allow
policies:
  - name: block-file-write
    tools: ["write_*"]
    action: deny
"""
        )
        output_path = tmp_path / "avakill.rules"
        generate_codex_rules(policy_path, output_path)

        content = output_path.read_text()
        # Should have a comment about skipping, not a prefix_rule
        assert "prefix_rule" not in content
        assert "skipped" in content.lower() or "non-shell" in content.lower()

    def test_generates_header_comment(self, tmp_path: Path) -> None:
        from avakill.hooks.openai_codex import generate_codex_rules

        policy_path = tmp_path / "avakill.yaml"
        policy_path.write_text(
            """
version: "1.0"
default_action: allow
policies: []
"""
        )
        output_path = tmp_path / "avakill.rules"
        generate_codex_rules(policy_path, output_path)

        content = output_path.read_text()
        assert "auto-generated" in content.lower() or "avakill" in content.lower()
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexInstaller -v`
Run: `pytest tests/test_hooks_openai_codex.py::TestCodexRulesGeneration -v`
Expected: FAIL — `KeyError: "unknown agent: 'openai-codex'"` and `ImportError`

**Step 3: Add `generate_codex_rules()` to `src/avakill/hooks/openai_codex.py`**

Append before the `main()` function:

```python
def generate_codex_rules(policy_path: Path, output_path: Path) -> None:
    """Generate Codex exec policy .rules from an AvaKill policy file.

    Translates shell-related AvaKill policy rules into Codex's
    Starlark-based ``prefix_rule()`` format.  Non-shell rules are
    skipped with a comment.

    Args:
        policy_path: Path to the AvaKill YAML policy file.
        output_path: Path to write the generated ``.rules`` file.
    """
    import fnmatch

    import yaml

    data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policies = data.get("policies", [])

    lines: list[str] = [
        "# Auto-generated by AvaKill from: " + str(policy_path),
        "# Re-generate with: avakill hook install openai-codex",
        "#",
        "# NOTE: Only shell command rules can be expressed in Codex's",
        "# exec policy format.  File write, read, and MCP tool rules",
        "# require upstream pre-execution hook support.",
        "",
    ]

    _ACTION_MAP = {
        "deny": "forbidden",
        "allow": "allow",
        "require_approval": "prompt",
    }

    shell_patterns = {"shell*", "shell_execute", "shell_command", "Bash", "run_shell_command"}

    wrote_any = False
    for rule in policies:
        tools = rule.get("tools", [])
        action = rule.get("action", "")
        name = rule.get("name", "unnamed")
        codex_decision = _ACTION_MAP.get(action)
        if codex_decision is None:
            continue

        # Check if this rule targets shell tools.
        is_shell = any(
            fnmatch.fnmatch(st, tp) or fnmatch.fnmatch(tp, st)
            for tp in tools
            for st in shell_patterns
        )
        if not is_shell:
            lines.append(f"# Skipped non-shell rule: {name} (tools: {tools})")
            continue

        conditions = rule.get("conditions", {})
        args_match = conditions.get("args_match", {})
        command_allowlist = conditions.get("command_allowlist", [])

        # Generate from args_match command patterns.
        command_patterns = args_match.get("command", [])
        for pattern in command_patterns:
            tokens = pattern.strip().split()
            if tokens:
                pattern_str = ", ".join(f'"{t}"' for t in tokens)
                lines.append(f"prefix_rule(")
                lines.append(f'    pattern = [{pattern_str}],')
                lines.append(f'    decision = "{codex_decision}",')
                lines.append(f'    justification = "AvaKill rule: {name}",')
                lines.append(f")")
                lines.append("")
                wrote_any = True

        # Generate from command_allowlist.
        for cmd in command_allowlist:
            lines.append(f"prefix_rule(")
            lines.append(f'    pattern = ["{cmd}"],')
            lines.append(f'    decision = "{codex_decision}",')
            lines.append(f'    justification = "AvaKill rule: {name}",')
            lines.append(f")")
            lines.append("")
            wrote_any = True

        # Shell rule without specific patterns — add a comment.
        if not command_patterns and not command_allowlist:
            lines.append(
                f"# Rule '{name}' targets shell tools with {action} action"
                f" but has no command patterns — cannot generate prefix_rule."
            )

    if not wrote_any:
        lines.append("# No shell command rules found in policy.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
```

Add the `Path` import at the top of the file:

```python
from pathlib import Path
```

**Step 4: Add `_AGENT_CONFIG` entry and handle pending upstream in `src/avakill/hooks/installer.py`**

Add to `_AGENT_CONFIG` dict (after the `"windsurf"` entry, around line 101):

```python
    "openai-codex": {
        "config_path": Path.home() / ".codex" / "config.toml",
        "event": "before_tool_use",
        "pending_upstream": True,
        "hook_entry": lambda cmd: {"command": cmd},
    },
```

Modify `install_hook()` to check for `pending_upstream` flag. After `cfg = _AGENT_CONFIG[agent]` (around line 187), add:

```python
    if cfg.get("pending_upstream"):
        # Codex CLI doesn't support pre-execution hooks yet.
        # Generate exec policy rules for immediate shell protection.
        result = HookInstallResult(config_path=path, command=cmd)
        result.warnings.append(
            "Codex CLI does not yet support pre-execution hooks. "
            "The AvaKill adapter is ready and will activate when upstream "
            "support ships. See https://github.com/openai/codex/issues/2109"
        )

        # Generate exec policy rules if a policy file is available.
        policy_path_env = os.environ.get("AVAKILL_POLICY")
        if policy_path_env:
            from avakill.hooks.openai_codex import generate_codex_rules

            rules_path = Path.home() / ".codex" / "rules" / "avakill.rules"
            try:
                generate_codex_rules(Path(policy_path_env), rules_path)
                result.warnings.append(
                    f"Generated exec policy rules at {rules_path} for shell command protection."
                )
            except Exception as exc:
                result.warnings.append(f"Failed to generate exec policy rules: {exc}")

        return result
```

Add `import os` at the top of `installer.py` if not already present.

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexInstaller tests/test_hooks_openai_codex.py::TestCodexRulesGeneration -v`
Expected: All 5 tests PASS

**Step 6: Commit**

```bash
git add src/avakill/hooks/openai_codex.py src/avakill/hooks/installer.py tests/test_hooks_openai_codex.py
git commit -m "feat: add Codex exec policy rules generation and installer support"
```

---

### Task 8: CLI Updates

**Files:**
- Modify: `src/avakill/cli/hook_cmd.py` — add `"openai-codex"` to Choice lists and agent arrays

**Step 1: Write the failing test**

Append to `tests/test_hooks_openai_codex.py`:

```python
from click.testing import CliRunner


class TestOpenAICodexCLI:
    """Test CLI integration for Codex hook commands."""

    def test_hook_list_includes_openai_codex(self) -> None:
        from avakill.cli.hook_cmd import hook

        runner = CliRunner()
        result = runner.invoke(hook, ["list"])
        assert result.exit_code == 0
        assert "openai-codex" in result.output
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexCLI -v`
Expected: FAIL — `openai-codex` not in output

**Step 3: Update `src/avakill/cli/hook_cmd.py`**

Make these changes:

1. Line 18 — update the `click.Choice` for `install`:
   ```python
   type=click.Choice(["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex", "all"]),
   ```

2. Line 27 — update the "all" agent list:
   ```python
   agents = ["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"] if agent == "all" else [agent]
   ```

3. Line 79 — update the `click.Choice` for `uninstall`:
   ```python
   type=click.Choice(["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex", "all"]),
   ```

4. Line 88 — update the "all" agent list in uninstall:
   ```python
   agents = ["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"] if agent == "all" else [agent]
   ```

5. Line 115 — update the `list_hooks` loop:
   ```python
   for agent in ("claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"):
   ```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_hooks_openai_codex.py::TestOpenAICodexCLI -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/avakill/cli/hook_cmd.py tests/test_hooks_openai_codex.py
git commit -m "feat: add openai-codex to hook CLI commands"
```

---

### Task 9: Full Test Suite Verification

**Files:** None (verification only)

**Step 1: Run the full Codex adapter test suite**

Run: `pytest tests/test_hooks_openai_codex.py -v`
Expected: All tests PASS (approximately 25 tests)

**Step 2: Run the existing hook tests to verify no regressions**

Run: `pytest tests/test_hooks_claude_code.py tests/test_hooks_gemini_cli.py tests/test_hooks_cursor.py tests/test_hooks_windsurf.py tests/test_hooks_installer.py -v`
Expected: All existing tests PASS

**Step 3: Run make check (lint + typecheck + test)**

Run: `make check`
Expected: All checks pass. Fix any lint or type errors found.

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: resolve lint/type issues from Codex adapter"
```

---

### Task 10: Manual Smoke Test

**Step 1: Test the entry point binary**

Run: `echo '{"tool_name": "shell", "tool_input": {"command": "rm -rf /"}}' | python -m avakill.hooks.openai_codex`
Expected: Exits with code 2 (parse succeeds but daemon not running) or processes through standalone mode if `AVAKILL_POLICY` is set.

**Step 2: Test `avakill hook list`**

Run: `python -m avakill.cli.main hook list`
Expected: Table shows `openai-codex` row with detected/installed status.

**Step 3: Verify entry point is registered**

Run: `pip install -e . && avakill-hook-openai-codex <<< '{"tool_name": "shell", "tool_input": {"command": "echo hello"}}'`
Expected: Exits with error about daemon (expected in dev), not "command not found".
