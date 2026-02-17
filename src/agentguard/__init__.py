"""AgentGuard - Open-source safety firewall for AI agents."""

from agentguard.core.engine import Guard
from agentguard.core.exceptions import ConfigError, PolicyViolation, RateLimitExceeded
from agentguard.interceptors.decorator import protect

__version__ = "0.1.0"


def __getattr__(name: str):  # noqa: ANN001
    """Lazy imports for optional integration classes."""
    if name == "GuardedOpenAIClient":
        from agentguard.interceptors.openai_wrapper import GuardedOpenAIClient

        return GuardedOpenAIClient
    if name == "GuardedAnthropicClient":
        from agentguard.interceptors.anthropic_wrapper import GuardedAnthropicClient

        return GuardedAnthropicClient
    if name == "AgentGuardCallbackHandler":
        from agentguard.interceptors.langchain_handler import AgentGuardCallbackHandler

        return AgentGuardCallbackHandler
    if name == "MCPProxyServer":
        from agentguard.mcp.proxy import MCPProxyServer

        return MCPProxyServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Guard",
    "protect",
    "PolicyViolation",
    "ConfigError",
    "RateLimitExceeded",
    "GuardedOpenAIClient",
    "GuardedAnthropicClient",
    "AgentGuardCallbackHandler",
    "MCPProxyServer",
]
