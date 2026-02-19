"""Compliance framework definitions and report models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    """A single compliance control assessment result."""

    control_id: str
    framework: str
    title: str
    description: str
    status: Literal["pass", "fail", "partial", "not_applicable"]
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    """Full compliance assessment report for a framework."""

    framework: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_status: Literal["compliant", "non_compliant", "partial"]
    controls: list[ComplianceControl]
    summary: str


# ---------------------------------------------------------------------------
# SOC 2 Type II controls relevant to AI agent safety
# ---------------------------------------------------------------------------

SOC2_CONTROLS: list[dict[str, str]] = [
    {
        "control_id": "SOC2-CC6.1",
        "title": "Logical and Physical Access Controls",
        "description": "The entity implements logical access security software, "
        "infrastructure, and architectures over protected information assets "
        "to protect them from security events.",
    },
    {
        "control_id": "SOC2-CC6.3",
        "title": "Role-Based Access and Least Privilege",
        "description": "The entity authorizes, modifies, or removes access to data, "
        "software, functions, and other protected information assets based on roles "
        "and the principle of least privilege.",
    },
    {
        "control_id": "SOC2-CC7.1",
        "title": "Detection of Unauthorized Changes",
        "description": "To meet its objectives, the entity uses detection and "
        "monitoring procedures to identify changes to configurations that result "
        "in the introduction of new vulnerabilities.",
    },
    {
        "control_id": "SOC2-CC7.2",
        "title": "Monitoring for Anomalies",
        "description": "The entity monitors system components and the operation "
        "of those components for anomalies that are indicative of malicious acts, "
        "natural disasters, and errors.",
    },
    {
        "control_id": "SOC2-CC8.1",
        "title": "Change Management",
        "description": "The entity authorizes, designs, develops or acquires, "
        "configures, documents, tests, approves, and implements changes to "
        "infrastructure, data, software, and procedures.",
    },
]


# ---------------------------------------------------------------------------
# NIST AI Risk Management Framework (AI RMF) functions
# ---------------------------------------------------------------------------

NIST_CONTROLS: list[dict[str, str]] = [
    {
        "control_id": "NIST-GOVERN",
        "title": "Govern",
        "description": "Policies, processes, procedures, and practices across the "
        "organization related to the mapping, measuring, and managing of AI risks "
        "are in place, transparent, and implemented effectively.",
    },
    {
        "control_id": "NIST-MAP",
        "title": "Map",
        "description": "Context is recognized and risks related to context are "
        "identified. AI actors understand the limitations of AI systems.",
    },
    {
        "control_id": "NIST-MEASURE",
        "title": "Measure",
        "description": "AI risks are assessed, analyzed, or tracked. Risk metrics "
        "are quantified and monitored over time.",
    },
    {
        "control_id": "NIST-MANAGE",
        "title": "Manage",
        "description": "AI risks are prioritized and acted upon. Risk treatments "
        "are planned, performed, and effectiveness is evaluated.",
    },
]


# ---------------------------------------------------------------------------
# EU AI Act relevant articles
# ---------------------------------------------------------------------------

EU_AI_ACT_CONTROLS: list[dict[str, str]] = [
    {
        "control_id": "EU-AI-ACT-Art9",
        "title": "Risk Management System",
        "description": "High-risk AI systems shall have a risk management system "
        "established, documented, implemented, and maintained as a continuous "
        "iterative process throughout the entire lifecycle.",
    },
    {
        "control_id": "EU-AI-ACT-Art12",
        "title": "Record-Keeping",
        "description": "High-risk AI systems shall technically allow for automatic "
        "recording of events (logs) over the lifetime of the system.",
    },
    {
        "control_id": "EU-AI-ACT-Art14",
        "title": "Human Oversight",
        "description": "High-risk AI systems shall be designed and developed in such "
        "a way that they can be effectively overseen by natural persons during the "
        "period in which the AI system is in use.",
    },
]


# ---------------------------------------------------------------------------
# ISO 42001 AI Management System controls
# ---------------------------------------------------------------------------

ISO_42001_CONTROLS: list[dict[str, str]] = [
    {
        "control_id": "ISO42001-A.2.3",
        "title": "AI Policy",
        "description": "The organization shall establish an AI policy appropriate to "
        "the purpose of the organization and provide a framework for setting AI objectives.",
    },
    {
        "control_id": "ISO42001-A.5",
        "title": "Resources for AI Systems",
        "description": "The organization shall determine and provide resources needed "
        "for the establishment, implementation, maintenance, and continual improvement "
        "of the AI management system.",
    },
    {
        "control_id": "ISO42001-A.6",
        "title": "Planning for AI Systems",
        "description": "The organization shall plan actions to address risks and "
        "opportunities related to AI systems.",
    },
    {
        "control_id": "ISO42001-A.7",
        "title": "Support and Operation",
        "description": "The organization shall plan, implement, and control processes "
        "needed to meet requirements and implement actions for AI systems.",
    },
    {
        "control_id": "ISO42001-A.8",
        "title": "Performance Evaluation",
        "description": "The organization shall determine what needs to be monitored "
        "and measured for AI systems, including methods and frequency.",
    },
]


FRAMEWORKS: dict[str, list[dict[str, str]]] = {
    "soc2": SOC2_CONTROLS,
    "nist-ai-rmf": NIST_CONTROLS,
    "eu-ai-act": EU_AI_ACT_CONTROLS,
    "iso-42001": ISO_42001_CONTROLS,
}
