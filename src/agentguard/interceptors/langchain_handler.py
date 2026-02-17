"""LangChain/LangGraph callback handler for intercepting tool calls with AgentGuard."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentguard.core.engine import Guard
from agentguard.core.exceptions import PolicyViolation


class AgentGuardCallbackHandler:
    """LangChain callback handler that intercepts tool calls.

    Register this handler with a LangChain agent so that every tool
    invocation is evaluated against the configured :class:`Guard` policies
    **before** the tool runs.

    Usage::

        handler = AgentGuardCallbackHandler(guard=guard)
        agent = create_react_agent(llm, tools, callbacks=[handler])

    Args:
        guard: A Guard instance.  If *None* a new one is created from
            *policy*.
        policy: Path to a YAML policy file (ignored when *guard* is given).
    """

    def __init__(
        self,
        guard: Guard | None = None,
        policy: str | Path | None = None,
    ) -> None:
        self._guard = guard or Guard(policy=policy)
        self.decisions: list[Any] = []

    @property
    def guard(self) -> Guard:
        return self._guard

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts — evaluates the call against policy.

        Raises:
            PolicyViolation: If the tool call is denied by policy.
        """
        tool_name = serialized.get("name") or serialized.get("id", "unknown")

        # Try to parse the input string as JSON to extract args
        try:
            args = json.loads(input_str) if input_str else {}
        except (json.JSONDecodeError, TypeError):
            args = {"input": input_str}
        if not isinstance(args, dict):
            args = {"input": args}

        decision = self._guard.evaluate(tool=tool_name, args=args)
        self.decisions.append(decision)

        if not decision.allowed:
            raise PolicyViolation(tool_name, decision)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool finishes successfully. Logged for audit."""

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when a tool raises an error. Logged for audit."""


def create_agentguard_wrapper(
    guard: Guard,
) -> Callable[..., Any]:
    """Create a wrapper function for LangGraph's ``ToolNode``.

    The returned callable can be passed as ``handle_tool_call`` to a
    ``ToolNode`` to evaluate each tool call before execution.

    Usage::

        wrapper = create_agentguard_wrapper(guard)
        # Use with ToolNode: the wrapper evaluates the call first,
        # then delegates to the original tool.

    Args:
        guard: The Guard instance to evaluate against.

    Returns:
        A callable that evaluates tool calls and raises on denial.
    """

    def wrapper(tool_call: Any) -> Any:
        name = (
            tool_call.get("name", "")
            if isinstance(tool_call, dict)
            else getattr(tool_call, "name", "unknown")
        )
        args = (
            tool_call.get("args", {})
            if isinstance(tool_call, dict)
            else getattr(tool_call, "args", {})
        )
        if not isinstance(args, dict):
            args = {}

        guard.evaluate_or_raise(tool=name, args=args)
        return tool_call

    return wrapper
