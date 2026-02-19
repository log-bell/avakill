"""Compliance assessor that checks policy configuration against framework controls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from avakill.compliance.frameworks import (
    FRAMEWORKS,
    ComplianceControl,
    ComplianceReport,
)

if TYPE_CHECKING:
    from avakill.core.engine import Guard
    from avakill.logging.sqlite_logger import SQLiteLogger


class ComplianceAssessor:
    """Check a Guard's policy configuration against compliance framework controls.

    Usage::

        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        print(report.overall_status)
    """

    def __init__(
        self,
        guard: Guard,
        logger: SQLiteLogger | None = None,
    ) -> None:
        self._guard = guard
        self._logger = logger

    def assess(self, framework: str) -> ComplianceReport:
        """Assess the guard's policy against a specific compliance framework.

        Args:
            framework: One of "soc2", "nist-ai-rmf", "eu-ai-act", "iso-42001".

        Returns:
            A ComplianceReport with per-control assessments.

        Raises:
            KeyError: If the framework is not recognized.
        """
        if framework not in FRAMEWORKS:
            raise KeyError(f"Unknown framework '{framework}'. Available: {', '.join(FRAMEWORKS)}")

        controls = self._assess_framework(framework)
        overall = self._compute_overall(controls)
        summary = self._build_summary(framework, controls)

        return ComplianceReport(
            framework=framework,
            overall_status=overall,
            controls=controls,
            summary=summary,
        )

    def assess_all(self) -> dict[str, ComplianceReport]:
        """Assess against all known compliance frameworks."""
        return {fw: self.assess(fw) for fw in FRAMEWORKS}

    # ------------------------------------------------------------------
    # Framework-specific assessment routing
    # ------------------------------------------------------------------

    def _assess_framework(self, framework: str) -> list[ComplianceControl]:
        """Dispatch to per-framework assessment logic."""
        checks: dict[str, list[ComplianceControl]] = {
            "soc2": self._assess_soc2(),
            "nist-ai-rmf": self._assess_nist(),
            "eu-ai-act": self._assess_eu_ai_act(),
            "iso-42001": self._assess_iso_42001(),
        }
        return checks[framework]

    # ------------------------------------------------------------------
    # SOC 2 Type II
    # ------------------------------------------------------------------

    def _assess_soc2(self) -> list[ComplianceControl]:
        return [
            self._check_deny_by_default(
                "SOC2-CC6.1",
                "SOC 2 Type II",
                "Logical and Physical Access Controls",
            ),
            self._check_rate_limiting(
                "SOC2-CC6.3",
                "SOC 2 Type II",
                "Role-Based Access and Least Privilege",
            ),
            self._check_policy_signing(
                "SOC2-CC7.1",
                "SOC 2 Type II",
                "Detection of Unauthorized Changes",
            ),
            self._check_audit_logging(
                "SOC2-CC7.2",
                "SOC 2 Type II",
                "Monitoring for Anomalies",
            ),
            self._check_self_protection(
                "SOC2-CC8.1",
                "SOC 2 Type II",
                "Change Management",
            ),
        ]

    # ------------------------------------------------------------------
    # NIST AI RMF
    # ------------------------------------------------------------------

    def _assess_nist(self) -> list[ComplianceControl]:
        return [
            self._check_deny_by_default(
                "NIST-GOVERN",
                "NIST AI RMF",
                "Govern",
            ),
            self._check_self_protection(
                "NIST-MAP",
                "NIST AI RMF",
                "Map",
            ),
            self._check_audit_logging(
                "NIST-MEASURE",
                "NIST AI RMF",
                "Measure",
            ),
            self._check_rate_limiting(
                "NIST-MANAGE",
                "NIST AI RMF",
                "Manage",
            ),
        ]

    # ------------------------------------------------------------------
    # EU AI Act
    # ------------------------------------------------------------------

    def _assess_eu_ai_act(self) -> list[ComplianceControl]:
        return [
            self._check_deny_by_default(
                "EU-AI-ACT-Art9",
                "EU AI Act",
                "Risk Management System",
            ),
            self._check_audit_logging(
                "EU-AI-ACT-Art12",
                "EU AI Act",
                "Record-Keeping",
            ),
            self._check_human_in_the_loop(
                "EU-AI-ACT-Art14",
                "EU AI Act",
                "Human Oversight",
            ),
        ]

    # ------------------------------------------------------------------
    # ISO 42001
    # ------------------------------------------------------------------

    def _assess_iso_42001(self) -> list[ComplianceControl]:
        return [
            self._check_deny_by_default(
                "ISO42001-A.2.3",
                "ISO 42001",
                "AI Policy",
            ),
            self._check_self_protection(
                "ISO42001-A.5",
                "ISO 42001",
                "Resources for AI Systems",
            ),
            self._check_rate_limiting(
                "ISO42001-A.6",
                "ISO 42001",
                "Planning for AI Systems",
            ),
            self._check_audit_logging(
                "ISO42001-A.7",
                "ISO 42001",
                "Support and Operation",
            ),
            self._check_policy_signing(
                "ISO42001-A.8",
                "ISO 42001",
                "Performance Evaluation",
            ),
        ]

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_deny_by_default(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that the policy uses deny-by-default."""
        config = self._guard.engine.config
        if config.default_action == "deny":
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Default action is deny (allowlist approach).",
                status="pass",
                evidence=["default_action=deny in policy configuration"],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="Default action is allow (permissive).",
            status="fail",
            evidence=["default_action=allow in policy configuration"],
            recommendations=["Set default_action to 'deny' for a secure allowlist approach."],
        )

    def _check_audit_logging(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that audit logging is configured."""
        has_logger = self._guard._logger is not None
        if has_logger:
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Audit logging is configured.",
                status="pass",
                evidence=["AuditLogger instance attached to Guard"],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="No audit logger configured.",
            status="fail",
            evidence=["Guard has no AuditLogger attached"],
            recommendations=[
                "Attach a SQLiteLogger or other AuditLogger to the Guard "
                "for persistent audit trails."
            ],
        )

    def _check_policy_signing(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that policy integrity verification (signing) is enabled."""
        has_integrity = self._guard._integrity is not None
        if has_integrity:
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Policy signing and integrity verification enabled.",
                status="pass",
                evidence=["PolicyIntegrity instance attached to Guard"],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="Policy signing is not configured.",
            status="fail",
            evidence=["Guard has no PolicyIntegrity (no signing/verify key)"],
            recommendations=[
                "Generate a signing key with 'avakill keygen' and sign policies "
                "with 'avakill sign' for tamper detection."
            ],
        )

    def _check_self_protection(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that self-protection rules are enabled."""
        has_sp = self._guard._self_protection is not None
        if has_sp:
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Self-protection rules are active.",
                status="pass",
                evidence=[
                    "SelfProtection instance prevents agents from weakening their own guardrails"
                ],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="Self-protection is disabled.",
            status="fail",
            evidence=["Guard initialized with self_protection=False"],
            recommendations=[
                "Enable self-protection (default) to prevent agents from "
                "modifying their own policy files or guardrail configuration."
            ],
        )

    def _check_rate_limiting(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that at least one policy rule has rate limiting."""
        config = self._guard.engine.config
        has_rate_limit = any(rule.rate_limit is not None for rule in config.policies)
        if has_rate_limit:
            rate_limited = [rule.name for rule in config.policies if rule.rate_limit is not None]
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Rate limiting is configured.",
                status="pass",
                evidence=[f"Rate-limited rules: {', '.join(rate_limited)}"],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="No rate limiting configured.",
            status="partial",
            evidence=["No policy rules have rate_limit set"],
            recommendations=[
                "Add rate_limit to high-volume tool rules to prevent abuse and resource exhaustion."
            ],
        )

    def _check_human_in_the_loop(
        self, control_id: str, framework: str, title: str
    ) -> ComplianceControl:
        """Check that at least one rule uses require_approval action."""
        config = self._guard.engine.config
        has_approval = any(rule.action == "require_approval" for rule in config.policies)
        if has_approval:
            approval_rules = [
                rule.name for rule in config.policies if rule.action == "require_approval"
            ]
            return ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=title,
                description="Human-in-the-loop approval workflow configured.",
                status="pass",
                evidence=[f"Rules requiring approval: {', '.join(approval_rules)}"],
            )
        return ComplianceControl(
            control_id=control_id,
            framework=framework,
            title=title,
            description="No human-in-the-loop approval rules.",
            status="fail",
            evidence=["No policy rules use action=require_approval"],
            recommendations=[
                "Add require_approval action to sensitive tool rules "
                "to enable human oversight of high-risk operations."
            ],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_overall(
        controls: list[ComplianceControl],
    ) -> Literal["compliant", "non_compliant", "partial"]:
        """Compute overall compliance status from individual controls."""
        statuses = {c.status for c in controls}
        if statuses <= {"pass", "not_applicable"}:
            return "compliant"
        if "fail" in statuses:
            return "non_compliant"
        return "partial"

    @staticmethod
    def _build_summary(framework: str, controls: list[ComplianceControl]) -> str:
        """Build a human-readable summary line."""
        total = len(controls)
        passed = sum(1 for c in controls if c.status == "pass")
        failed = sum(1 for c in controls if c.status == "fail")
        partial = sum(1 for c in controls if c.status == "partial")
        parts = [f"{passed}/{total} controls passing"]
        if failed:
            parts.append(f"{failed} failing")
        if partial:
            parts.append(f"{partial} partial")
        return f"{framework}: {', '.join(parts)}."
