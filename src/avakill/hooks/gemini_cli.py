"""Gemini CLI hook adapter.

Translates Gemini CLI's BeforeTool JSON payload into AvaKill's
wire protocol.  Gemini CLI mirrors Claude Code's hook contract
but uses snake_case tool names and regex matchers.

Gemini CLI stdin payload::

    {
      "session_id": "...",
      "hook_event_name": "BeforeTool",
      "tool_name": "run_shell_command",
      "tool_input": {"command": "rm -rf /"},
      "tool_use_id": "..."
    }

Deny response (JSON on stdout, exit 0)::

    {
      "hookSpecificOutput": {
        "hookEventName": "BeforeTool",
        "permissionDecision": "deny",
        "reason": "..."
      }
    }
"""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


@register_adapter
class GeminiCLIAdapter(HookAdapter):
    """Hook adapter for Gemini CLI."""

    agent_name = "gemini-cli"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Gemini CLI BeforeTool payload."""
        data = json.loads(raw)

        tool = data["tool_name"]
        args = data.get("tool_input", {})

        context: dict[str, object] = {}
        for key in ("session_id", "cwd", "tool_use_id"):
            if key in data:
                context[key] = data[key]

        # Gemini CLI also sets GEMINI_CWD / GEMINI_PROJECT_DIR as env vars.
        return EvaluateRequest(
            agent=self.agent_name,
            event=data.get("hook_event_name", "BeforeTool"),
            tool=tool,
            args=args if isinstance(args, dict) else {},
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Gemini CLI.

        Gemini CLI uses exit codes to determine hook outcome:
        - Exit 0: allow (tool proceeds)
        - Exit 2: block (tool is aborted, stderr shown as reason)

        For deny, we write the reason to stderr and exit 2.
        For allow, no output and exit 0.
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy and response.policy != "self-protection":
                reason = f"{reason} [{response.policy}]. Run `avakill fix` for recovery steps."
            elif not response.policy:
                reason = f"{reason}. Run `avakill fix` for recovery steps."
            # self-protection messages are already complete
            # Gemini CLI reads stderr for the rejection reason on exit 2
            import sys

            print(reason, file=sys.stderr)
            return None, 2

        if response.decision == "require_approval":
            payload = {
                "hookSpecificOutput": {
                    "hookEventName": "BeforeTool",
                    "permissionDecision": "ask",
                }
            }
            return json.dumps(payload), 0

        # Allow — no output.
        return None, 0


def main() -> None:
    """Entry point for the ``avakill-hook-gemini`` console script."""
    GeminiCLIAdapter().run()
