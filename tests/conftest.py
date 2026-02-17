"""Shared test fixtures for AgentGuard."""

from pathlib import Path

import pytest

from agentguard.core.models import PolicyConfig, PolicyRule


@pytest.fixture
def sample_policy() -> PolicyConfig:
    """Create a sample policy for testing."""
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
            PolicyRule(name="deny-delete", tools=["file_delete"], action="deny"),
            PolicyRule(
                name="ask-write",
                tools=["file_write"],
                action="require_approval",
            ),
        ],
    )


@pytest.fixture
def tmp_policy_file(tmp_path: Path) -> Path:
    """Create a temporary policy YAML file."""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
    )
    return policy_file


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "test_audit.db"
