"""Pydantic models for agent containment profiles."""

from __future__ import annotations

from pydantic import BaseModel, Field

from avakill.core.models import SandboxConfig


class AgentMetadata(BaseModel):
    """Metadata about an AI agent for containment profiling."""

    name: str
    display_name: str = ""
    command: list[str] = Field(default_factory=list)
    detect_paths: list[str] = Field(default_factory=list)
    detect_commands: list[str] = Field(default_factory=list)
    supports_hooks: bool = False
    mcp_native: bool = False
    description: str = ""


class AgentProfile(BaseModel):
    """Complete containment profile for an AI agent.

    Combines agent metadata with a sandbox configuration.
    Built-in profiles ship as YAML files in src/avakill/profiles/.
    Users can override any field via the policy cascade.
    """

    agent: AgentMetadata
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
