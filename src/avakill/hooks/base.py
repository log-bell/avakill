"""Abstract base class for agent hook adapters.

Each adapter translates between an agent's native hook payload
(received on stdin) and the AvaKill daemon wire protocol.

Evaluation order (fallback chain):

1. Self-protection (always, no policy needed)
2. ``AVAKILL_POLICY`` env var → standalone eval
3. Running daemon → ``try_evaluate()``
4. Auto-discover ``avakill.yaml`` / ``avakill.yml`` in cwd → standalone eval
5. No policy source → allow with stderr warning
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import NoReturn

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

    def output_response(self, response: EvaluateResponse) -> int:
        """Format and write the response, returning the exit code.

        The default implementation writes to stdout.  Subclasses may
        override to write to stderr (e.g. Windsurf).
        """
        stdout, exit_code = self.format_response(response)
        if stdout is not None:
            print(stdout, end="", file=sys.stdout)
        return exit_code

    def run(self, stdin_data: str | None = None) -> NoReturn:
        """Read stdin, evaluate via the fallback chain, format output, and exit.

        Fallback chain:

        1. Self-protection (always, no policy needed)
        2. ``AVAKILL_POLICY`` env var → standalone eval
        3. Running daemon → ``try_evaluate()``
        4. Auto-discover ``avakill.yaml`` / ``avakill.yml`` in cwd
        5. No policy source → allow with stderr warning
        """
        raw = stdin_data if stdin_data is not None else sys.stdin.read()

        try:
            request = self.parse_stdin(raw)
        except (ValueError, json.JSONDecodeError, KeyError) as exc:
            # Malformed input — fail-closed (deny).
            print(f"avakill: failed to parse stdin: {exc}", file=sys.stderr)
            sys.exit(2)

        # --- Fallback chain ---

        # 1. Self-protection (hardcoded, no policy needed)
        response = self._check_self_protection(request)
        if response is not None:
            exit_code = self.output_response(response)
            sys.exit(exit_code)

        # 2. AVAKILL_POLICY env var → standalone eval
        policy_path = os.environ.get("AVAKILL_POLICY")
        if policy_path:
            response = self._evaluate_standalone(request, policy_path)
            exit_code = self.output_response(response)
            sys.exit(exit_code)

        # 3. Running daemon → try_evaluate (returns None if unreachable)
        response = self._try_daemon(request)
        if response is not None:
            exit_code = self.output_response(response)
            sys.exit(exit_code)

        # 4. Auto-discover avakill.yaml / avakill.yml in cwd
        response = self._try_local_policy(request)
        if response is not None:
            exit_code = self.output_response(response)
            sys.exit(exit_code)

        # 5. No policy source → check fail-closed mode
        fail_closed = os.environ.get("AVAKILL_FAIL_CLOSED", "").strip()
        if fail_closed in ("1", "true", "yes"):
            print(
                "avakill: no policy source found and AVAKILL_FAIL_CLOSED is set. "
                "Denying tool call.",
                file=sys.stderr,
            )
            response = EvaluateResponse(
                decision="deny", reason="no policy source (fail-closed mode)"
            )
            exit_code = self.output_response(response)
            sys.exit(exit_code)

        # 6. No policy source, fail-open → allow with warning
        print(
            "avakill: no policy source found (no AVAKILL_POLICY, no daemon, "
            "no avakill.yaml in cwd). Allowing tool call. "
            "Run `avakill init --template hooks` to create a policy.",
            file=sys.stderr,
        )
        response = EvaluateResponse(decision="allow", reason="no policy source")
        exit_code = self.output_response(response)
        sys.exit(exit_code)

    # ------------------------------------------------------------------
    # Fallback chain helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_self_protection(request: EvaluateRequest) -> EvaluateResponse | None:
        """Run hardcoded self-protection checks before any policy.

        Returns a deny :class:`EvaluateResponse` if the tool call is
        blocked, or ``None`` to continue the fallback chain.
        """
        from avakill.core.models import ToolCall
        from avakill.core.normalization import normalize_tool_name
        from avakill.core.self_protection import SelfProtection

        canonical_tool = normalize_tool_name(request.tool, request.agent)
        tool_call = ToolCall(tool_name=canonical_tool, arguments=request.args or {})

        decision = SelfProtection().check(tool_call)
        if decision is not None:
            return EvaluateResponse(
                decision="deny",
                reason=decision.reason,
                policy="self-protection",
            )
        return None

    @staticmethod
    def _try_daemon(request: EvaluateRequest) -> EvaluateResponse | None:
        """Try the daemon, returning ``None`` if unreachable."""
        from avakill.daemon.client import DaemonClient

        client = DaemonClient()
        return client.try_evaluate(request)

    @staticmethod
    def _try_local_policy(request: EvaluateRequest) -> EvaluateResponse | None:
        """Look for ``avakill.yaml`` or ``avakill.yml`` in the cwd."""
        cwd = Path.cwd()
        for name in ("avakill.yaml", "avakill.yml"):
            candidate = cwd / name
            if candidate.is_file():
                return HookAdapter._evaluate_standalone(request, str(candidate))
        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_standalone(request: EvaluateRequest, policy_path: str) -> EvaluateResponse:
        """Evaluate directly without the daemon (standalone mode).

        Applies tool normalization before evaluation so that policies
        written with canonical names work in standalone mode too.
        """
        import time

        from avakill.core.approval import ApprovalStore
        from avakill.core.engine import Guard
        from avakill.core.normalization import normalize_tool_name

        canonical_tool = normalize_tool_name(request.tool, request.agent)

        store = ApprovalStore()
        guard = Guard(policy=policy_path, approval_store=store)
        t0 = time.perf_counter()
        decision = guard.evaluate(tool=canonical_tool, args=request.args)
        latency = (time.perf_counter() - t0) * 1000

        return EvaluateResponse(
            decision=decision.action,
            reason=decision.reason,
            policy=decision.policy_name,
            latency_ms=round(latency, 2),
        )
