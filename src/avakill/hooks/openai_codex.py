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
