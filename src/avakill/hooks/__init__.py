"""Agent hook adapters for AvaKill.

Each supported AI coding agent gets a thin adapter that translates
between the agent's native hook JSON format and AvaKill's daemon
wire protocol (:class:`~avakill.daemon.protocol.EvaluateRequest` /
:class:`~avakill.daemon.protocol.EvaluateResponse`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avakill.hooks.base import HookAdapter

ADAPTERS: dict[str, type[HookAdapter]] = {}


def register_adapter(cls: type[HookAdapter]) -> type[HookAdapter]:
    """Class decorator that registers an adapter in the global registry."""
    ADAPTERS[cls.agent_name] = cls
    return cls


def get_adapter(agent: str) -> type[HookAdapter]:
    """Look up an adapter by agent name.

    Raises:
        KeyError: If no adapter is registered for *agent*.
    """
    # Lazy-import concrete adapters so the registry is populated.
    if not ADAPTERS:
        _import_all()
    try:
        return ADAPTERS[agent]
    except KeyError:
        raise KeyError(f"unknown agent: {agent!r}; known: {sorted(ADAPTERS)}") from None


def _import_all() -> None:
    """Import all adapter modules to trigger registration."""
    import avakill.hooks.claude_code as _cc  # noqa: F811, F401
    import avakill.hooks.cursor as _cu  # noqa: F811, F401
    import avakill.hooks.gemini_cli as _gc  # noqa: F811, F401
    import avakill.hooks.openai_codex as _oc  # noqa: F811, F401
    import avakill.hooks.windsurf as _ws  # noqa: F811, F401
