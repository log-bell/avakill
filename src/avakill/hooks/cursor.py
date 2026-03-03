"""Cursor hook adapter.

Translates Cursor hook payloads (``beforeShellExecution``,
``beforeMCPExecution``, ``beforeReadFile``, ``preToolUse``) into
AvaKill's wire protocol.  Cursor uses JSON responses (not exit codes)
for control — always exit 0.

Legacy events (beforeShellExecution, beforeMCPExecution, beforeReadFile)
use ``permission`` / ``agentMessage`` response format.

preToolUse uses ``decision`` / ``reason`` response format.
"""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


@register_adapter
class CursorAdapter(HookAdapter):
    """Hook adapter for Cursor."""

    agent_name = "cursor"

    _last_event: str = "beforeShellExecution"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Cursor hook payload."""
        data = json.loads(raw)

        event = data.get("hook_event_name", "beforeShellExecution")
        self._last_event = event

        # Cursor doesn't have a unified tool_name field — derive from event.
        if event == "beforeShellExecution":
            tool = "shell_command"
            args: dict[str, object] = {}
            if "command" in data:
                args["command"] = data["command"]
            if "cwd" in data:
                args["cwd"] = data["cwd"]
        elif event == "beforeMCPExecution":
            tool = data.get("tool_name", "mcp_tool")
            args = data.get("tool_input", {})
        elif event == "beforeReadFile":
            tool = "read_file"
            args = {}
            if "file_path" in data:
                args["file_path"] = data["file_path"]
        elif event == "preToolUse":
            tool = data.get("tool_name", "unknown_tool")
            args = data.get("tool_input", {})
        else:
            tool = event
            args = {}

        context: dict[str, object] = {}
        for key in ("conversation_id", "generation_id", "workspace_roots"):
            if key in data:
                context[key] = data[key]

        return EvaluateRequest(
            agent=self.agent_name,
            event=event,
            tool=tool,
            args=args if isinstance(args, dict) else {},
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Cursor.

        Cursor always expects JSON on stdout and exit 0.
        ``preToolUse`` uses ``decision``/``reason`` keys; legacy events
        use ``permission``/``agentMessage``.
        """
        event = self._last_event

        reason = response.reason or "Blocked by AvaKill policy"
        if response.policy:
            reason = f"{reason} [{response.policy}]"

        # preToolUse uses decision/reason format.
        if event == "preToolUse":
            if response.decision == "deny":
                reason = f"{reason}. Run `avakill fix` for recovery steps."
                return json.dumps({"decision": "deny", "reason": reason}), 0
            if response.decision == "require_approval":
                return json.dumps({"decision": "deny", "reason": "Requires manual approval"}), 0
            return json.dumps({"decision": "allow"}), 0

        # Legacy events: permission/agentMessage format.
        if response.decision == "deny":
            reason = f"{reason}. Run `avakill fix` for recovery steps."
            return json.dumps({"permission": "deny", "agentMessage": reason}), 0

        if response.decision == "require_approval":
            return json.dumps({"permission": "ask"}), 0

        return json.dumps({"permission": "allow"}), 0


def main() -> None:
    """Entry point for the ``avakill-hook-cursor`` console script."""
    CursorAdapter().run()
