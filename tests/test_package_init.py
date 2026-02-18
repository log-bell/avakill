"""Tests for avakill package-level __init__.py lazy imports."""

import pytest

import avakill


def test_version():
    assert avakill.__version__ == "0.1.0"


def test_core_exports():
    assert avakill.Guard is not None
    assert avakill.protect is not None
    assert avakill.PolicyViolation is not None
    assert avakill.ConfigError is not None
    assert avakill.RateLimitExceeded is not None


def test_lazy_import_guarded_openai_client():
    cls = avakill.GuardedOpenAIClient
    from avakill.interceptors.openai_wrapper import GuardedOpenAIClient

    assert cls is GuardedOpenAIClient


def test_lazy_import_guarded_anthropic_client():
    cls = avakill.GuardedAnthropicClient
    from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient

    assert cls is GuardedAnthropicClient


def test_lazy_import_callback_handler():
    cls = avakill.AvaKillCallbackHandler
    from avakill.interceptors.langchain_handler import AvaKillCallbackHandler

    assert cls is AvaKillCallbackHandler


def test_lazy_import_mcp_proxy_server():
    cls = avakill.MCPProxyServer
    from avakill.mcp.proxy import MCPProxyServer

    assert cls is MCPProxyServer


def test_lazy_import_unknown_raises():
    with pytest.raises(AttributeError, match="has no attribute"):
        _ = avakill.NonExistentThing


def test_all_exports():
    expected = {
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
    }
    assert set(avakill.__all__) == expected
