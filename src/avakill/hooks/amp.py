"""Amp CLI hook adapter.

Translates Amp CLI's permissions delegation mechanism into AvaKill's
wire protocol.  Amp uses environment variables for tool identification
and stdin for tool arguments.

Contract:
- ``AGENT_TOOL_NAME`` env var: tool name
- ``AGENT_THREAD_ID`` env var: thread context (optional)
- stdin: JSON tool arguments
- Exit 0: allow
- Exit 1: ask (prompt operator)
- Exit >= 2: reject (stderr message surfaced to model)
"""

from __future__ import annotations

import json
import os

from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse
from avakill.hooks import register_adapter
from avakill.hooks.base import HookAdapter


@register_adapter
class AmpAdapter(HookAdapter):
    """Hook adapter for Amp CLI."""

    agent_name = "amp"

    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse Amp CLI tool arguments from stdin + env vars."""
        tool = os.environ.get("AGENT_TOOL_NAME", "unknown")

        try:
            args = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            args = {}

        if not isinstance(args, dict):
            args = {"raw": args}

        context: dict[str, object] = {}
        thread_id = os.environ.get("AGENT_THREAD_ID")
        if thread_id:
            context["thread_id"] = thread_id

        return EvaluateRequest(
            agent=self.agent_name,
            event="pre_tool_use",
            tool=tool,
            args=args,
            context=context,
        )

    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format the decision for Amp CLI.

        Amp uses exit codes:
        - Exit 0: allow
        - Exit 1: ask (prompt operator — Amp's native approval)
        - Exit >= 2: reject (stderr message surfaced to model)
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
            return None, 1  # Amp native "ask" support

        # Allow — no output.
        return None, 0


def main() -> None:
    """Entry point for the ``avakill-hook-amp`` console script."""
    AmpAdapter().run()
