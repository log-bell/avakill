"""Tests for the protect decorator."""

from __future__ import annotations

import inspect

import pytest

from agentguard.core.engine import Guard
from agentguard.core.exceptions import PolicyViolation
from agentguard.core.models import PolicyConfig, PolicyRule
from agentguard.interceptors.decorator import protect


@pytest.fixture
def guard() -> Guard:
    policy = PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-read", tools=["read_file"], action="allow"),
            PolicyRule(name="allow-greet", tools=["greet"], action="allow"),
            PolicyRule(name="deny-delete", tools=["delete_file"], action="deny"),
        ],
    )
    return Guard(policy=policy)


class TestProtectSync:
    """Tests for the protect decorator on synchronous functions."""

    def test_allowed_call_executes(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="read_file")
        def read_file(path: str) -> str:
            return f"contents of {path}"

        result = read_file("/tmp/x")
        assert result == "contents of /tmp/x"

    def test_denied_call_raises(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="delete_file")
        def delete_file(path: str) -> None:
            pass

        with pytest.raises(PolicyViolation) as exc_info:
            delete_file("/etc/passwd")
        assert exc_info.value.tool_name == "delete_file"

    def test_uses_function_name_by_default(self, guard: Guard) -> None:
        @protect(guard=guard)
        def read_file(path: str) -> str:
            return "ok"

        # function name "read_file" matches allow-read rule
        assert read_file("/tmp/x") == "ok"

    def test_custom_tool_name(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="delete_file")
        def my_innocent_function() -> str:
            return "should not run"

        with pytest.raises(PolicyViolation):
            my_innocent_function()

    def test_passes_args_to_policy(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="read_file")
        def read_file(path: str, mode: str = "r") -> dict:
            return {"path": path, "mode": mode}

        result = read_file("/tmp/x", mode="rb")
        assert result == {"path": "/tmp/x", "mode": "rb"}

    def test_preserves_function_metadata(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="read_file")
        def my_func() -> None:
            """My docstring."""

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."


class TestProtectAsync:
    """Tests for the protect decorator on async functions."""

    async def test_allowed_async_executes(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="read_file")
        async def read_file(path: str) -> str:
            return f"async {path}"

        result = await read_file("/tmp/x")
        assert result == "async /tmp/x"

    async def test_denied_async_raises(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="delete_file")
        async def delete_file(path: str) -> None:
            pass

        with pytest.raises(PolicyViolation):
            await delete_file("/etc/passwd")

    async def test_async_preserves_coroutine(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="read_file")
        async def read_file() -> str:
            return "async result"

        # The wrapper should return a coroutine
        assert inspect.iscoroutinefunction(read_file)


class TestProtectOnDeny:
    """Tests for on_deny modes."""

    def test_on_deny_raise(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="delete_file", on_deny="raise")
        def delete_file() -> None:
            pass

        with pytest.raises(PolicyViolation):
            delete_file()

    def test_on_deny_return_none(self, guard: Guard) -> None:
        @protect(guard=guard, tool_name="delete_file", on_deny="return_none")
        def delete_file() -> str:
            return "should not run"

        result = delete_file()
        assert result is None

    def test_on_deny_callback(self, guard: Guard) -> None:
        deny_log: list = []

        def on_denied(tool_name, decision, args, kwargs):
            deny_log.append({"tool": tool_name, "allowed": decision.allowed})
            return "denied"

        @protect(
            guard=guard,
            tool_name="delete_file",
            on_deny="callback",
            deny_callback=on_denied,
        )
        def delete_file() -> str:
            return "should not run"

        result = delete_file()
        assert result == "denied"
        assert len(deny_log) == 1
        assert deny_log[0]["tool"] == "delete_file"
        assert deny_log[0]["allowed"] is False


class TestProtectBareDecorator:
    """Tests for using @protect without parentheses."""

    def test_bare_decorator_with_auto_detect(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_file = tmp_path / "agentguard.yaml"  # type: ignore[operator]
        policy_file.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies:\n"
            "  - name: allow-all\n    tools: ['*']\n    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)

        @protect
        def greet(name: str) -> str:
            return f"hello {name}"

        assert greet("world") == "hello world"


class TestProtectWithPolicy:
    """Tests for providing a policy path instead of a guard."""

    def test_policy_path(self, tmp_path: pytest.TempPathFactory) -> None:
        policy_file = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\npolicies:\n"
            "  - name: allow-greet\n    tools: [greet]\n    action: allow\n"
        )

        @protect(policy=policy_file)
        def greet() -> str:
            return "hi"

        assert greet() == "hi"

    def test_policy_path_denies(self, tmp_path: pytest.TempPathFactory) -> None:
        policy_file = tmp_path / "policy.yaml"  # type: ignore[operator]
        policy_file.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")

        @protect(policy=policy_file)
        def anything() -> str:
            return "nope"

        with pytest.raises(PolicyViolation):
            anything()
