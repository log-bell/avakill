"""Tests for the Anthropic interceptor."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig, PolicyRule
from avakill.interceptors.anthropic_wrapper import (
    GuardedAnthropicClient,
    evaluate_tool_use_blocks,
)

# ---------------------------------------------------------------------------
# Mock helpers — simulate Anthropic response objects
# ---------------------------------------------------------------------------


def _text_block(text: str = "Hello") -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(
    name: str,
    input_: dict | None = None,
    block_id: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        type="tool_use",
        id=block_id or f"toolu_{name}",
        name=name,
        input=input_ or {},
    )


def _make_response(content: list | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id="msg_test",
        type="message",
        role="assistant",
        content=content or [],
        model="claude-sonnet-4-5-20250514",
        stop_reason="tool_use" if content else "end_turn",
    )


def _make_mock_client(response: SimpleNamespace) -> MagicMock:
    client = MagicMock()
    client.messages.create.return_value = response
    return client


@pytest.fixture
def guard() -> Guard:
    policy = PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-search", tools=["search"], action="allow"),
            PolicyRule(name="allow-read", tools=["read_file"], action="allow"),
            PolicyRule(name="deny-delete", tools=["delete_file"], action="deny"),
        ],
    )
    return Guard(policy=policy)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEvaluateToolUseBlocks:
    """Tests for the standalone evaluate_tool_use_blocks function."""

    def test_only_evaluates_tool_use(self, guard: Guard) -> None:
        blocks = [_text_block("hi"), _tool_use_block("search", {"q": "test"})]
        results = evaluate_tool_use_blocks(guard, blocks)
        assert len(results) == 1
        assert results[0][0].name == "search"
        assert results[0][1].allowed is True

    def test_denied_tool(self, guard: Guard) -> None:
        blocks = [_tool_use_block("delete_file", {"path": "/etc"})]
        results = evaluate_tool_use_blocks(guard, blocks)
        assert len(results) == 1
        assert results[0][1].allowed is False

    def test_mixed_blocks(self, guard: Guard) -> None:
        blocks = [
            _tool_use_block("search", {"q": "hello"}),
            _tool_use_block("delete_file", {"path": "/etc"}),
        ]
        results = evaluate_tool_use_blocks(guard, blocks)
        assert results[0][1].allowed is True
        assert results[1][1].allowed is False

    def test_no_tool_use_blocks(self, guard: Guard) -> None:
        blocks = [_text_block("just text")]
        results = evaluate_tool_use_blocks(guard, blocks)
        assert results == []


class TestGuardedAnthropicClient:
    """Tests for GuardedAnthropicClient."""

    def test_wrap_client(self, guard: Guard) -> None:
        client = MagicMock()
        guarded = GuardedAnthropicClient(client, guard=guard)
        assert guarded.guard is guard

    def test_no_content_passes_through(self, guard: Guard) -> None:
        response = _make_response(content=[])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        assert result.avakill_decisions == []

    def test_text_only_passes_through(self, guard: Guard) -> None:
        response = _make_response(content=[_text_block("hello world")])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].text == "hello world"
        assert result.avakill_decisions == []

    def test_allowed_tool_use_preserved(self, guard: Guard) -> None:
        tu = _tool_use_block("search", {"q": "test"})
        response = _make_response(content=[_text_block("thinking..."), tu])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        # Both text and tool_use should remain
        assert len(result.content) == 2
        assert result.content[1].name == "search"
        assert len(result.avakill_decisions) == 1
        assert result.avakill_decisions[0][1].allowed is True

    def test_denied_tool_use_removed(self, guard: Guard) -> None:
        tu = _tool_use_block("delete_file", {"path": "/etc"})
        response = _make_response(content=[_text_block("planning"), tu])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        # Only text block should remain
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        assert len(result.avakill_decisions) == 1
        assert result.avakill_decisions[0][1].allowed is False

    def test_mixed_tool_use_filtered(self, guard: Guard) -> None:
        allowed = _tool_use_block("search", {"q": "hello"})
        denied = _tool_use_block("delete_file", {"path": "/etc"})
        response = _make_response(content=[_text_block(), allowed, denied])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        # Text + allowed tool_use remain; denied is removed
        assert len(result.content) == 2
        tool_blocks = [b for b in result.content if b.type == "tool_use"]
        assert len(tool_blocks) == 1
        assert tool_blocks[0].name == "search"
        assert len(result.avakill_decisions) == 2

    def test_all_tool_use_denied(self, guard: Guard) -> None:
        d1 = _tool_use_block("delete_file", {"path": "/a"})
        d2 = _tool_use_block("delete_file", {"path": "/b"})
        response = _make_response(content=[d1, d2])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        assert result.content == []
        assert len(result.avakill_decisions) == 2

    def test_passthrough_attributes(self, guard: Guard) -> None:
        client = MagicMock()
        client.models.list.return_value = ["claude-3"]
        guarded = GuardedAnthropicClient(client, guard=guard)
        assert guarded.models.list() == ["claude-3"]

    def test_with_policy_path(self, tmp_path: pytest.TempPathFactory) -> None:
        policy_file = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        tu = _tool_use_block("anything")
        response = _make_response(content=[tu])
        client = _make_mock_client(response)

        guarded = GuardedAnthropicClient(client, policy=policy_file)
        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].name == "anything"

    def test_tool_use_with_input_args(self, guard: Guard) -> None:
        tu = _tool_use_block("search", {"q": "python", "limit": 10})
        response = _make_response(content=[tu])
        client = _make_mock_client(response)
        guarded = GuardedAnthropicClient(client, guard=guard)

        result = guarded.messages.create(model="claude-sonnet-4-5-20250514", messages=[])
        assert len(result.content) == 1
        assert result.avakill_decisions[0][1].allowed is True
