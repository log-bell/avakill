"""Tests for agentguard package-level __init__.py lazy imports."""

import pytest

import agentguard


def test_version():
    assert agentguard.__version__ == "0.1.0"


def test_core_exports():
    assert agentguard.Guard is not None
    assert agentguard.protect is not None
    assert agentguard.PolicyViolation is not None
    assert agentguard.ConfigError is not None
    assert agentguard.RateLimitExceeded is not None


def test_lazy_import_guarded_openai_client():
    cls = agentguard.GuardedOpenAIClient
    from agentguard.interceptors.openai_wrapper import GuardedOpenAIClient

    assert cls is GuardedOpenAIClient


def test_lazy_import_guarded_anthropic_client():
    cls = agentguard.GuardedAnthropicClient
    from agentguard.interceptors.anthropic_wrapper import GuardedAnthropicClient

    assert cls is GuardedAnthropicClient


def test_lazy_import_callback_handler():
    cls = agentguard.AgentGuardCallbackHandler
    from agentguard.interceptors.langchain_handler import AgentGuardCallbackHandler

    assert cls is AgentGuardCallbackHandler


def test_lazy_import_mcp_proxy_server():
    cls = agentguard.MCPProxyServer
    from agentguard.mcp.proxy import MCPProxyServer

    assert cls is MCPProxyServer


def test_lazy_import_unknown_raises():
    with pytest.raises(AttributeError, match="has no attribute"):
        _ = agentguard.NonExistentThing


def test_all_exports():
    expected = {
        "Guard",
        "protect",
        "PolicyViolation",
        "ConfigError",
        "RateLimitExceeded",
        "GuardedOpenAIClient",
        "GuardedAnthropicClient",
        "AgentGuardCallbackHandler",
        "MCPProxyServer",
    }
    assert set(agentguard.__all__) == expected
