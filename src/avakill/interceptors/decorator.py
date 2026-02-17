"""Decorator-based interceptor for wrapping functions with AvaKill policy checks."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, TypeVar, overload

from avakill.core.engine import Guard
from avakill.core.exceptions import PolicyViolation

T = TypeVar("T")


def _extract_args(fn: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    """Best-effort extraction of function arguments as a dict."""
    sig = inspect.signature(fn)
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        # Fall back to kwargs only
        return dict(kwargs)


@overload
def protect(fn: Callable[..., T]) -> Callable[..., T]: ...


@overload
def protect(
    fn: None = None,
    *,
    guard: Guard | None = None,
    policy: str | Path | None = None,
    tool_name: str | None = None,
    on_deny: Literal["raise", "return_none", "callback"] = "raise",
    deny_callback: Callable[..., Any] | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]: ...


def protect(
    fn: Callable[..., T] | None = None,
    *,
    guard: Guard | None = None,
    policy: str | Path | None = None,
    tool_name: str | None = None,
    on_deny: Literal["raise", "return_none", "callback"] = "raise",
    deny_callback: Callable[..., Any] | None = None,
) -> Callable[..., T] | Callable[[Callable[..., T]], Callable[..., T]]:
    """Wrap a function with AvaKill policy checks.

    Can be used with or without arguments::

        @protect
        def my_tool(): ...

        @protect(guard=guard, tool_name="custom_name")
        def my_tool(): ...

        @protect(policy="strict.yaml", on_deny="return_none")
        async def risky_tool(): ...

    Args:
        fn: The function to protect (when used without parentheses).
        guard: A Guard instance. If None and policy is given, one is created.
            If both are None, auto-detect policy.
        policy: Path to a YAML policy file (creates a Guard internally).
        tool_name: Override the tool name (defaults to ``fn.__name__``).
        on_deny: Behaviour when a call is denied:
            ``"raise"`` — raise ``PolicyViolation`` (default).
            ``"return_none"`` — silently return ``None``.
            ``"callback"`` — call ``deny_callback`` with the decision.
        deny_callback: Called when ``on_deny="callback"``; receives
            ``(tool_name, decision, args, kwargs)``.

    Returns:
        The wrapped function (or a decorator if called with arguments).
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        resolved_guard = guard
        name = tool_name or func.__name__

        def _get_guard() -> Guard:
            nonlocal resolved_guard
            if resolved_guard is None:
                resolved_guard = Guard(policy=policy)
            return resolved_guard

        def _handle_deny(decision: Any, f_args: tuple, f_kwargs: dict) -> Any:
            if on_deny == "return_none":
                return None
            if on_deny == "callback" and deny_callback is not None:
                return deny_callback(name, decision, f_args, f_kwargs)
            raise PolicyViolation(name, decision)

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                g = _get_guard()
                call_args = _extract_args(func, args, kwargs)
                decision = g.evaluate(tool=name, args=call_args)
                if not decision.allowed:
                    return _handle_deny(decision, args, kwargs)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            g = _get_guard()
            call_args = _extract_args(func, args, kwargs)
            decision = g.evaluate(tool=name, args=call_args)
            if not decision.allowed:
                return _handle_deny(decision, args, kwargs)
            return func(*args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]

    # Support bare @protect (no parentheses)
    if fn is not None:
        return decorator(fn)
    return decorator
