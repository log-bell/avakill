"""Tests for the LangChain callback handler."""

from __future__ import annotations

import json

import pytest

from agentguard.core.engine import Guard
from agentguard.core.exceptions import PolicyViolation
from agentguard.core.models import PolicyConfig, PolicyRule
from agentguard.interceptors.langchain_handler import (
    AgentGuardCallbackHandler,
    create_agentguard_wrapper,
)


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
# AgentGuardCallbackHandler
# ---------------------------------------------------------------------------


class TestAgentGuardCallbackHandler:
    """Tests for AgentGuardCallbackHandler."""

    def test_on_tool_start_allowed(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        # Should not raise
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str=json.dumps({"q": "hello"}),
        )
        assert len(handler.decisions) == 1
        assert handler.decisions[0].allowed is True

    def test_on_tool_start_denied_raises(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        with pytest.raises(PolicyViolation) as exc_info:
            handler.on_tool_start(
                serialized={"name": "delete_file"},
                input_str=json.dumps({"path": "/etc/passwd"}),
            )
        assert exc_info.value.tool_name == "delete_file"
        assert len(handler.decisions) == 1
        assert handler.decisions[0].allowed is False

    def test_on_tool_start_uses_id_fallback(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        handler.on_tool_start(
            serialized={"id": "search"},
            input_str="{}",
        )
        assert handler.decisions[0].allowed is True

    def test_on_tool_start_non_json_input(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="hello world",
        )
        # Non-JSON input is wrapped as {"input": "hello world"}
        assert handler.decisions[0].allowed is True

    def test_on_tool_start_empty_input(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="",
        )
        assert handler.decisions[0].allowed is True

    def test_on_tool_end_does_not_raise(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        # Should be a no-op
        handler.on_tool_end(output="some result")

    def test_on_tool_error_does_not_raise(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        # Should be a no-op
        handler.on_tool_error(error=RuntimeError("boom"))

    def test_multiple_tool_calls_tracked(self, guard: Guard) -> None:
        handler = AgentGuardCallbackHandler(guard=guard)
        handler.on_tool_start({"name": "search"}, "{}")
        handler.on_tool_start({"name": "read_file"}, "{}")
        assert len(handler.decisions) == 2
        assert all(d.allowed for d in handler.decisions)

    def test_with_policy_path(self, tmp_path: pytest.TempPathFactory) -> None:
        policy_file = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\n"
            "policies:\n  - name: allow\n    tools: [search]\n    action: allow\n"
        )
        handler = AgentGuardCallbackHandler(policy=policy_file)
        handler.on_tool_start({"name": "search"}, "{}")
        assert handler.decisions[0].allowed is True


# ---------------------------------------------------------------------------
# create_agentguard_wrapper
# ---------------------------------------------------------------------------


class TestCreateAgentguardWrapper:
    """Tests for create_agentguard_wrapper (LangGraph ToolNode support)."""

    def test_allowed_tool_call_dict(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)
        tc = {"name": "search", "args": {"q": "hello"}}
        result = wrapper(tc)
        # Should pass through unchanged
        assert result is tc

    def test_denied_tool_call_raises(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)
        tc = {"name": "delete_file", "args": {"path": "/etc"}}
        with pytest.raises(PolicyViolation) as exc_info:
            wrapper(tc)
        assert exc_info.value.tool_name == "delete_file"

    def test_tool_call_as_object(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)

        class FakeToolCall:
            name = "search"
            args = {"q": "test"}

        result = wrapper(FakeToolCall())
        assert result.name == "search"

    def test_denied_tool_call_as_object(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)

        class FakeToolCall:
            name = "delete_file"
            args = {"path": "/etc"}

        with pytest.raises(PolicyViolation):
            wrapper(FakeToolCall())

    def test_missing_args_defaults_to_empty(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)
        tc = {"name": "search"}
        # Should not raise; args defaults to {}
        result = wrapper(tc)
        assert result is tc

    def test_default_action_deny_for_unknown(self, guard: Guard) -> None:
        wrapper = create_agentguard_wrapper(guard)
        tc = {"name": "unknown_tool", "args": {}}
        with pytest.raises(PolicyViolation):
            wrapper(tc)
