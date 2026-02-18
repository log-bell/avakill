"""Abstract base class for agent hook adapters.

Each adapter translates between an agent's native hook payload
(received on stdin) and the AvaKill daemon wire protocol.
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from typing import NoReturn

from avakill.daemon.client import DaemonClient
from avakill.daemon.protocol import EvaluateRequest, EvaluateResponse


class HookAdapter(ABC):
    """Base class for all agent hook adapters.

    Subclasses must set :attr:`agent_name` and implement
    :meth:`parse_stdin` and :meth:`format_response`.
    """

    agent_name: str

    @abstractmethod
    def parse_stdin(self, raw: str) -> EvaluateRequest:
        """Parse the agent's native JSON payload into an EvaluateRequest.

        Args:
            raw: Raw string read from stdin.

        Returns:
            A populated :class:`EvaluateRequest`.

        Raises:
            ValueError: If *raw* cannot be parsed.
        """

    @abstractmethod
    def format_response(self, response: EvaluateResponse) -> tuple[str | None, int]:
        """Format an EvaluateResponse for the agent.

        Returns:
            A ``(stdout_output, exit_code)`` tuple.
            *stdout_output* is ``None`` when the adapter produces no output
            (e.g. a simple "allow" passthrough).
        """

    def run(self, stdin_data: str | None = None) -> NoReturn:
        """Read stdin, evaluate via daemon, format output, and exit.

        If *stdin_data* is ``None``, reads from :data:`sys.stdin`.
        Falls back to standalone mode when ``AVAKILL_POLICY`` is set.
        """
        raw = stdin_data if stdin_data is not None else sys.stdin.read()

        try:
            request = self.parse_stdin(raw)
        except (ValueError, json.JSONDecodeError, KeyError) as exc:
            # Malformed input — fail-closed (deny).
            print(f"avakill: failed to parse stdin: {exc}", file=sys.stderr)
            sys.exit(2)

        policy_path = os.environ.get("AVAKILL_POLICY")
        if policy_path:
            response = self._evaluate_standalone(request, policy_path)
        else:
            client = DaemonClient()
            response = client.evaluate(request)

        stdout, exit_code = self.format_response(response)
        if stdout is not None:
            print(stdout, end="")
        sys.exit(exit_code)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_standalone(
        request: EvaluateRequest, policy_path: str
    ) -> EvaluateResponse:
        """Evaluate directly without the daemon (standalone mode).

        Applies tool normalization before evaluation so that policies
        written with canonical names work in standalone mode too.
        """
        import time

        from avakill.core.engine import Guard
        from avakill.core.normalization import normalize_tool_name

        canonical_tool = normalize_tool_name(request.tool, request.agent)

        guard = Guard(policy=policy_path)
        t0 = time.perf_counter()
        decision = guard.evaluate(tool=canonical_tool, args=request.args)
        latency = (time.perf_counter() - t0) * 1000

        return EvaluateResponse(
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            policy=decision.policy_name,
            latency_ms=round(latency, 2),
        )
