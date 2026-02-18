"""Cursor hook adapter.

Translates Cursor's ``beforeShellExecution`` and ``beforeMCPExecution``
JSON payloads into AvaKill's wire protocol.  Cursor uses JSON responses
(not exit codes) for control — always exit 0.

Cursor stdin payload (beforeShellExecution)::

    {
      "conversation_id": "...",
      "generation_id": "...",
      "command": "git status",
      "cwd": "",
      "hook_event_name": "beforeShellExecution",
      "workspace_roots": ["/Users/user/project"]
    }

Deny response (JSON on stdout, exit 0)::

    {
      "continue": true,
      "permission": "deny",
      "agentMessage": "Blocked by AvaKill: ..."
    }

Allow response (JSON on stdout, exit 0)::

    {
      "continue": true,
      "permission": "allow"
    }
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

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Cursor beforeShellExecution / beforeMCPExecution payload."""
        data = json.loads(raw)

        event = data.get("hook_event_name", "beforeShellExecution")

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
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy:
                reason = f"{reason} [{response.policy}]"
            payload = {
                "continue": True,
                "permission": "deny",
                "agentMessage": reason,
            }
            return json.dumps(payload), 0

        if response.decision == "require_approval":
            payload = {
                "continue": True,
                "permission": "ask",
            }
            return json.dumps(payload), 0

        # Allow.
        payload = {
            "continue": True,
            "permission": "allow",
        }
        return json.dumps(payload), 0


def main() -> None:
    """Entry point for the ``avakill-hook-cursor`` console script."""
    CursorAdapter().run()
