"""Windsurf Cascade Hooks adapter.

Translates Windsurf's hook payloads (``pre_run_command``,
``pre_write_code``, ``pre_read_code``, ``pre_mcp_tool_use``) into
AvaKill's wire protocol.  Windsurf uses **exit code 2** for blocking
and stderr for the reason string.

Windsurf stdin payload (pre_run_command)::

    {
      "agent_action_name": "pre_run_command",
      "trajectory_id": "...",
      "execution_id": "...",
      "timestamp": "2026-02-18T14:23:05.000Z",
      "tool_info": {
        "command_line": "rm -rf /important-data",
        "cwd": "/home/user/project"
      }
    }

Deny: reason string on stderr, exit 2.
Allow: no output, exit 0.
"""

from __future__ import annotations

import json
import logging
import sys

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter

logger = logging.getLogger(__name__)

# Map Windsurf action names to tool names for policy evaluation.
_ACTION_TOOL_MAP: dict[str, str] = {
    "pre_run_command": "run_command",
    "pre_write_code": "write_code",
    "pre_read_code": "read_code",
    "pre_mcp_tool_use": "mcp_tool",
}


@register_adapter
class WindsurfAdapter(HookAdapter):
    """Hook adapter for Windsurf (Cascade Hooks)."""

    agent_name = "windsurf"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse a Windsurf hook payload."""
        data = json.loads(raw)

        action = data.get("agent_action_name", "")
        tool_info = data.get("tool_info", {})

        tool = _ACTION_TOOL_MAP.get(action, action)

        # Build args from tool_info based on the action type.
        args: dict[str, object] = {}
        if action == "pre_run_command":
            if "command_line" in tool_info:
                args["command"] = tool_info["command_line"]
            if "cwd" in tool_info:
                args["cwd"] = tool_info["cwd"]
        elif action == "pre_write_code":
            if "file_path" in tool_info:
                args["file_path"] = tool_info["file_path"]
            if "edits" in tool_info:
                args["edits"] = tool_info["edits"]
        elif action == "pre_read_code":
            if "file_path" in tool_info:
                args["file_path"] = tool_info["file_path"]
        elif action == "pre_mcp_tool_use":
            if "mcp_server_name" in tool_info:
                args["mcp_server_name"] = tool_info["mcp_server_name"]
            if "mcp_tool_name" in tool_info:
                args["mcp_tool_name"] = tool_info["mcp_tool_name"]
            if "mcp_tool_arguments" in tool_info:
                args["mcp_tool_arguments"] = tool_info["mcp_tool_arguments"]

        context: dict[str, object] = {}
        for key in ("trajectory_id", "execution_id", "timestamp"):
            if key in data:
                context[key] = data[key]

        return EvaluateRequest(
            agent=self.agent_name,
            event=action,
            tool=tool,
            args=args,
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Windsurf.

        - Deny: reason string (for stderr), exit 2.
        - Require approval: degraded to allow with stderr warning
          (Windsurf has no native approval mechanism).
        - Allow: no output, exit 0.
        """
        if response.decision == "deny":
            reason = response.reason or "Blocked by AvaKill policy"
            if response.policy and response.policy != "self-protection":
                reason = f"{reason} [{response.policy}]. Run `avakill fix` for recovery steps."
            elif not response.policy:
                reason = f"{reason}. Run `avakill fix` for recovery steps."
            # self-protection messages are already complete
            return reason, 2

        if response.decision == "require_approval":
            logger.warning(
                "Windsurf has no native approval mechanism; "
                "allowing tool that requires approval (policy: %s, reason: %s)",
                response.policy,
                response.reason,
            )
            print(
                "avakill: WARNING: Windsurf has no approval mechanism. "
                "Tool that requires approval is being ALLOWED. "
                f"Policy: {response.policy}, Reason: {response.reason}",
                file=sys.stderr,
            )

        # Allow (and require_approval treated as allow for now — Windsurf
        # has no native "ask" mechanism).
        return None, 0

    def output_response(self, response: EvaluateResponse) -> int:
        """Write deny reason to stderr (Windsurf convention)."""
        stdout, exit_code = self.format_response(response)
        if stdout is not None:
            print(stdout, end="", file=sys.stderr)
        return exit_code


def main() -> None:
    """Entry point for the ``avakill-hook-windsurf`` console script."""
    WindsurfAdapter().run()
