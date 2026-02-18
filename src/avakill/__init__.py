"""AvaKill — Open-source safety firewall for AI agents. She doesn't guard. She kills."""

from avakill.core.engine import Guard
from avakill.core.exceptions import ConfigError, PolicyViolation, RateLimitExceeded
from avakill.interceptors.decorator import protect

__version__ = "0.1.0"


def __getattr__(name: str):  # noqa: ANN001
    """Lazy imports for optional integration classes."""
    if name == "GuardedOpenAIClient":
        from avakill.interceptors.openai_wrapper import GuardedOpenAIClient

        return GuardedOpenAIClient
    if name == "GuardedAnthropicClient":
        from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient

        return GuardedAnthropicClient
    if name == "AvaKillCallbackHandler":
        from avakill.interceptors.langchain_handler import AvaKillCallbackHandler

        return AvaKillCallbackHandler
    if name == "MCPProxyServer":
        from avakill.mcp.proxy import MCPProxyServer

        return MCPProxyServer
    if name == "get_json_schema":
        from avakill.schema import get_json_schema

        return get_json_schema
    if name == "generate_prompt":
        from avakill.schema import generate_prompt

        return generate_prompt
    if name == "PolicyIntegrity":
        from avakill.core.integrity import PolicyIntegrity

        return PolicyIntegrity
    if name == "FileSnapshot":
        from avakill.core.integrity import FileSnapshot

        return FileSnapshot
    if name == "get_metrics_registry":
        from avakill.metrics import get_registry

        return get_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Guard",
    "protect",
    "PolicyViolation",
    "ConfigError",
    "RateLimitExceeded",
    "GuardedOpenAIClient",
    "GuardedAnthropicClient",
    "AvaKillCallbackHandler",
    "MCPProxyServer",
    "get_json_schema",
    "generate_prompt",
    "PolicyIntegrity",
    "FileSnapshot",
    "get_metrics_registry",
]
