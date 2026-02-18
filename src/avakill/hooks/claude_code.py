"""Claude Code hook adapter.

Translates Claude Code's PreToolUse JSON payload into AvaKill's
wire protocol and formats deny responses as ``hookSpecificOutput``
JSON that Claude Code understands.

Claude Code stdin payload::

    {
      "session_id": "...",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {"command": "rm -rf /"},
      "tool_use_id": "..."
    }

Deny response (JSON on stdout, exit 0)::

    {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "..."
      }
    }

Allow: no output, exit 0.
"""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


@register_adapter
class ClaudeCodeAdapter(HookAdapter):
    """Hook adapter for Claude Code."""

    agent_name = "claude-code"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Claude Code PreToolUse payload."""
        data = json.loads(raw)

        tool = data["tool_name"]
        args = data.get("tool_input", {})

        context: dict[str, object] = {}
        for key in ("session_id", "cwd", "permission_mode", "transcript_path", "tool_use_id"):
            if key in data:
                context[key] = data[key]

        return EvaluateRequest(
            agent=self.agent_name,
            event=data.get("hook_event_name", "PreToolUse"),
            tool=tool,
            args=args if isinstance(args, dict) else {},
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Claude Code.

        - Deny: JSON with ``hookSpecificOutput.permissionDecision = "deny"``, exit 0.
        - Allow: no output, exit 0.
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy:
                reason = f"{reason} [{response.policy}]"
            reason = f"{reason}. Run `avakill fix` for recovery steps."
            payload = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
            return json.dumps(payload), 0

        if response.decision == "require_approval":
            payload = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                }
            }
            return json.dumps(payload), 0

        # Allow — no output.
        return None, 0


def main() -> None:
    """Entry point for the ``avakill-hook-claude`` console script."""
    ClaudeCodeAdapter().run()
