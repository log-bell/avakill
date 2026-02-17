"""OpenAI interceptor that wraps an OpenAI client with AgentGuard policy checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentguard.core.engine import Guard
from agentguard.core.models import Decision


def evaluate_tool_calls(
    guard: Guard,
    tool_calls: list[Any],
) -> list[tuple[Any, Decision]]:
    """Evaluate a list of OpenAI tool call objects and return decisions.

    Args:
        guard: The Guard instance to evaluate against.
        tool_calls: A list of OpenAI tool call objects (each has
            ``function.name`` and ``function.arguments``).

    Returns:
        A list of ``(tool_call, decision)`` tuples.
    """
    results: list[tuple[Any, Decision]] = []
    for tc in tool_calls:
        name = tc.function.name
        try:
            args = json.loads(tc.function.arguments)
        except (json.JSONDecodeError, TypeError):
            args = {}
        decision = guard.evaluate(tool=name, args=args)
        results.append((tc, decision))
    return results


class _GuardedCompletions:
    """Proxy for ``client.chat.completions`` that intercepts ``create``."""

    def __init__(self, completions: Any, guard: Guard) -> None:
        self._completions = completions
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        response = self._completions.create(*args, **kwargs)
        return self._process_response(response)

    async def acreate(self, *args: Any, **kwargs: Any) -> Any:
        # For the async OpenAI client the method is still called `create`
        # on AsyncCompletions, but we keep acreate as a convenience alias.
        response = await self._completions.create(*args, **kwargs)
        return self._process_response(response)

    def _process_response(self, response: Any) -> Any:
        decisions: list[tuple[Any, Decision]] = []
        for choice in response.choices:
            msg = choice.message
            if not getattr(msg, "tool_calls", None):
                continue
            evaluated = evaluate_tool_calls(self._guard, msg.tool_calls)
            decisions.extend(evaluated)

            allowed_calls = [tc for tc, d in evaluated if d.allowed]
            msg.tool_calls = allowed_calls or None

        response.agentguard_decisions = decisions  # type: ignore[attr-defined]
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _GuardedChat:
    """Proxy for ``client.chat`` that provides guarded ``completions``."""

    def __init__(self, chat: Any, guard: Guard) -> None:
        self._chat = chat
        self._guard = guard
        self.completions = _GuardedCompletions(chat.completions, guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class GuardedOpenAIClient:
    """Wraps an OpenAI client to automatically intercept function calls.

    Usage::

        from openai import OpenAI
        client = OpenAI()
        guarded = GuardedOpenAIClient(client, policy="agentguard.yaml")

        response = guarded.chat.completions.create(
            model="gpt-4o",
            tools=[...],
            messages=[...],
        )
        # Denied tool_calls are removed from the response.
        # All decisions are available on response.agentguard_decisions

    Args:
        client: An OpenAI client instance.
        guard: A Guard instance.  If *None* a new one is created from
            *policy*.
        policy: Path to a YAML policy file (ignored when *guard* is given).
    """

    def __init__(
        self,
        client: Any,
        guard: Guard | None = None,
        policy: str | Path | None = None,
    ) -> None:
        self._client = client
        self._guard = guard or Guard(policy=policy)
        self.chat = _GuardedChat(client.chat, self._guard)

    @property
    def guard(self) -> Guard:
        return self._guard

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
