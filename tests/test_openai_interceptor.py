"""Tests for the OpenAI interceptor."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig, PolicyRule
from avakill.interceptors.openai_wrapper import (
    GuardedOpenAIClient,
    evaluate_tool_calls,
)

# ---------------------------------------------------------------------------
# Mock helpers — simulate OpenAI response objects
# ---------------------------------------------------------------------------


def _make_tool_call(name: str, arguments: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=f"call_{name}",
        type="function",
        function=SimpleNamespace(
            name=name,
            arguments=json.dumps(arguments or {}),
        ),
    )


def _make_response(tool_calls: list | None = None, text: str = "") -> SimpleNamespace:
    message = SimpleNamespace(
        role="assistant",
        content=text,
        tool_calls=tool_calls,
    )
    choice = SimpleNamespace(
        index=0,
        message=message,
        finish_reason="tool_calls" if tool_calls else "stop",
    )
    return SimpleNamespace(
        id="chatcmpl-test",
        choices=[choice],
        model="gpt-4o",
    )


def _make_mock_client(response: SimpleNamespace) -> MagicMock:
    """Create a mock OpenAI client that returns the given response."""
    client = MagicMock()
    client.chat.completions.create.return_value = response
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


class TestEvaluateToolCalls:
    """Tests for the standalone evaluate_tool_calls function."""

    def test_all_allowed(self, guard: Guard) -> None:
        tcs = [_make_tool_call("search", {"q": "hello"})]
        results = evaluate_tool_calls(guard, tcs)
        assert len(results) == 1
        assert results[0][1].allowed is True

    def test_all_denied(self, guard: Guard) -> None:
        tcs = [_make_tool_call("delete_file", {"path": "/etc"})]
        results = evaluate_tool_calls(guard, tcs)
        assert len(results) == 1
        assert results[0][1].allowed is False

    def test_mixed(self, guard: Guard) -> None:
        tcs = [
            _make_tool_call("search", {"q": "hello"}),
            _make_tool_call("delete_file", {"path": "/etc"}),
        ]
        results = evaluate_tool_calls(guard, tcs)
        assert results[0][1].allowed is True
        assert results[1][1].allowed is False

    def test_invalid_json_args(self, guard: Guard) -> None:
        tc = SimpleNamespace(
            id="call_bad",
            type="function",
            function=SimpleNamespace(name="search", arguments="not json"),
        )
        results = evaluate_tool_calls(guard, [tc])
        assert len(results) == 1
        # Should still evaluate (with empty args)
        assert results[0][1].allowed is True


class TestGuardedOpenAIClient:
    """Tests for GuardedOpenAIClient."""

    def test_wrap_client(self, guard: Guard) -> None:
        client = MagicMock()
        guarded = GuardedOpenAIClient(client, guard=guard)
        assert guarded.guard is guard

    def test_no_tool_calls_passes_through(self, guard: Guard) -> None:
        response = _make_response(tool_calls=None, text="Hello!")
        client = _make_mock_client(response)
        guarded = GuardedOpenAIClient(client, guard=guard)

        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        assert result.choices[0].message.content == "Hello!"
        assert result.avakill_decisions == []

    def test_allowed_tool_calls_preserved(self, guard: Guard) -> None:
        tcs = [_make_tool_call("search", {"q": "test"})]
        response = _make_response(tool_calls=tcs)
        client = _make_mock_client(response)
        guarded = GuardedOpenAIClient(client, guard=guard)

        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        assert result.choices[0].message.tool_calls == tcs
        assert len(result.avakill_decisions) == 1
        assert result.avakill_decisions[0][1].allowed is True

    def test_denied_tool_calls_removed(self, guard: Guard) -> None:
        tcs = [_make_tool_call("delete_file", {"path": "/etc"})]
        response = _make_response(tool_calls=tcs)
        client = _make_mock_client(response)
        guarded = GuardedOpenAIClient(client, guard=guard)

        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        # Denied calls are removed (set to None when all removed)
        assert result.choices[0].message.tool_calls is None
        assert len(result.avakill_decisions) == 1
        assert result.avakill_decisions[0][1].allowed is False

    def test_mixed_tool_calls_filtered(self, guard: Guard) -> None:
        allowed_tc = _make_tool_call("search", {"q": "hello"})
        denied_tc = _make_tool_call("delete_file", {"path": "/etc"})
        response = _make_response(tool_calls=[allowed_tc, denied_tc])
        client = _make_mock_client(response)
        guarded = GuardedOpenAIClient(client, guard=guard)

        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        remaining = result.choices[0].message.tool_calls
        assert len(remaining) == 1
        assert remaining[0].function.name == "search"
        assert len(result.avakill_decisions) == 2

    def test_multiple_choices(self, guard: Guard) -> None:
        msg1 = SimpleNamespace(
            role="assistant",
            content=None,
            tool_calls=[_make_tool_call("search")],
        )
        msg2 = SimpleNamespace(
            role="assistant",
            content=None,
            tool_calls=[_make_tool_call("delete_file")],
        )
        response = SimpleNamespace(
            id="chatcmpl-multi",
            choices=[
                SimpleNamespace(index=0, message=msg1, finish_reason="tool_calls"),
                SimpleNamespace(index=1, message=msg2, finish_reason="tool_calls"),
            ],
            model="gpt-4o",
        )
        client = MagicMock()
        client.chat.completions.create.return_value = response
        guarded = GuardedOpenAIClient(client, guard=guard)

        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        # Choice 0: search allowed
        assert result.choices[0].message.tool_calls is not None
        assert len(result.choices[0].message.tool_calls) == 1
        # Choice 1: delete_file denied
        assert result.choices[1].message.tool_calls is None
        assert len(result.avakill_decisions) == 2

    def test_passthrough_attributes(self, guard: Guard) -> None:
        client = MagicMock()
        client.models.list.return_value = ["gpt-4o"]
        guarded = GuardedOpenAIClient(client, guard=guard)
        assert guarded.models.list() == ["gpt-4o"]

    def test_with_policy_path(self, tmp_path: pytest.TempPathFactory) -> None:
        policy_file = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        client = MagicMock()
        tcs = [_make_tool_call("anything")]
        client.chat.completions.create.return_value = _make_response(tool_calls=tcs)

        guarded = GuardedOpenAIClient(client, policy=policy_file)
        result = guarded.chat.completions.create(model="gpt-4o", messages=[])
        assert result.choices[0].message.tool_calls is not None
