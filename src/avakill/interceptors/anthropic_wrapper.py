"""Anthropic interceptor that wraps an Anthropic client with AvaKill policy checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from avakill.core.engine import Guard
from avakill.core.models import Decision


def evaluate_tool_use_blocks(
    guard: Guard,
    content_blocks: list[Any],
) -> list[tuple[Any, Decision]]:
    """Evaluate tool_use content blocks and return decisions.

    Args:
        guard: The Guard instance to evaluate against.
        content_blocks: Content blocks from an Anthropic message response.

    Returns:
        A list of ``(block, decision)`` tuples for each tool_use block.
    """
    results: list[tuple[Any, Decision]] = []
    for block in content_blocks:
        block_type = getattr(block, "type", None)
        if block_type != "tool_use":
            continue
        name = block.name
        args = block.input if isinstance(block.input, dict) else {}
        decision = guard.evaluate(tool=name, args=args)
        results.append((block, decision))
    return results


class _GuardedMessages:
    """Proxy for ``client.messages`` that intercepts ``create``."""

    def __init__(self, messages: Any, guard: Guard) -> None:
        self._messages = messages
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        response = self._messages.create(*args, **kwargs)
        return self._process_response(response)

    async def acreate(self, *args: Any, **kwargs: Any) -> Any:
        response = await self._messages.create(*args, **kwargs)
        return self._process_response(response)

    def _process_response(self, response: Any) -> Any:
        content = getattr(response, "content", None)
        if not content:
            response.avakill_decisions = []  # type: ignore[attr-defined]
            return response

        evaluated = evaluate_tool_use_blocks(self._guard, content)

        denied_ids = {id(block) for block, d in evaluated if not d.allowed}
        filtered = [b for b in content if id(b) not in denied_ids]
        response.content = filtered

        response.avakill_decisions = evaluated  # type: ignore[attr-defined]
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class GuardedAnthropicClient:
    """Wraps an Anthropic client to automatically intercept tool use blocks.

    Usage::

        from anthropic import Anthropic
        client = Anthropic()
        guarded = GuardedAnthropicClient(client, policy="avakill.yaml")

        response = guarded.messages.create(
            model="claude-sonnet-4-5-20250514",
            tools=[...],
            messages=[...],
        )
        # Denied tool_use blocks are removed from response.content.
        # All decisions are available on response.avakill_decisions

    Args:
        client: An Anthropic client instance.
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
        self.messages = _GuardedMessages(client.messages, self._guard)

    @property
    def guard(self) -> Guard:
        return self._guard

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
