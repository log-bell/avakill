"""Kiro CLI hook adapter.

Translates Kiro CLI's PreToolUse JSON payload into AvaKill's
wire protocol.  Kiro CLI mirrors Claude Code/Gemini CLI's hook
contract with stdin JSON and exit-code-based decisions.

Kiro CLI stdin payload::

    {
      "hook_event_name": "PreToolUse",
      "cwd": "/path/to/project",
      "tool_name": "execute_bash",
      "tool_input": {"command": "rm -rf /"}
    }

Deny: stderr message + exit 2.
Allow: no output + exit 0.
"""

from __future__ import annotations

import json

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


@register_adapter
class KiroAdapter(HookAdapter):
    """Hook adapter for Kiro CLI."""

    agent_name = "kiro"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Kiro CLI PreToolUse payload."""
        data = json.loads(raw)

        tool = data["tool_name"]
        args = data.get("tool_input", {})

        context: dict[str, object] = {}
        for key in ("cwd",):
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
        """Format the decision for Kiro CLI.

        Kiro CLI uses exit codes to determine hook outcome:
        - Exit 0: allow (tool proceeds)
        - Exit 2: block (tool is aborted, stderr shown as reason)

        Kiro has no native "ask" mechanism, so require_approval
        is treated as deny (exit 2).
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy and response.policy != "self-protection":
                reason = f"{reason} [{response.policy}]. Run `avakill fix` for recovery steps."
            elif not response.policy:
                reason = f"{reason}. Run `avakill fix` for recovery steps."
            import sys

            print(reason, file=sys.stderr)
            return None, 2

        if response.decision == "require_approval":
            import sys

            reason = "This action requires approval. Run `avakill fix` for details."
            print(reason, file=sys.stderr)
            return None, 2  # Kiro has no "ask" mechanism — block

        # Allow — no output.
        return None, 0


def main() -> None:
    """Entry point for the ``avakill-hook-kiro`` console script."""
    KiroAdapter().run()
