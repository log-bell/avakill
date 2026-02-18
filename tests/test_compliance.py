"""Tests for compliance assessment."""

from __future__ import annotations

import pytest

from avakill.compliance.assessor import ComplianceAssessor
from avakill.compliance.frameworks import FRAMEWORKS
from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig, PolicyRule, RateLimit
from avakill.logging.sqlite_logger import SQLiteLogger


class TestComplianceAssessor:
    """Tests for ComplianceAssessor."""

    def _make_guard(
        self,
        *,
        default_action: str = "deny",
        self_protection: bool = True,
        logger: SQLiteLogger | None = None,
        signing_key: bytes | None = None,
        rules: list[PolicyRule] | None = None,
    ) -> Guard:
        if rules is None:
            rules = [
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
            ]
        policy = PolicyConfig(
            version="1.0",
            default_action=default_action,
            policies=rules,
        )
        return Guard(
            policy=policy,
            self_protection=self_protection,
            logger=logger,
            signing_key=signing_key,
        )

    def test_assess_soc2_returns_report(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        assert report.framework == "soc2"
        assert len(report.controls) == 5
        assert report.overall_status in ("compliant", "non_compliant", "partial")

    def test_assess_nist_returns_report(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("nist-ai-rmf")
        assert report.framework == "nist-ai-rmf"
        assert len(report.controls) == 4

    def test_assess_eu_ai_act_returns_report(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("eu-ai-act")
        assert report.framework == "eu-ai-act"
        assert len(report.controls) == 3

    def test_assess_iso_42001_returns_report(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("iso-42001")
        assert report.framework == "iso-42001"
        assert len(report.controls) == 5

    def test_assess_all_returns_all_frameworks(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        reports = assessor.assess_all()
        assert set(reports.keys()) == set(FRAMEWORKS.keys())
        for fw, report in reports.items():
            assert report.framework == fw

    def test_deny_by_default_passes(self) -> None:
        guard = self._make_guard(default_action="deny")
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc61 = next(c for c in report.controls if c.control_id == "SOC2-CC6.1")
        assert cc61.status == "pass"

    def test_allow_by_default_fails_access_control(self) -> None:
        guard = self._make_guard(default_action="allow")
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc61 = next(c for c in report.controls if c.control_id == "SOC2-CC6.1")
        assert cc61.status == "fail"

    def test_signing_enabled_passes_integrity_check(self) -> None:
        # We can't easily configure real signing with a PolicyConfig object,
        # but we can check that _check_policy_signing detects the _integrity attr.
        guard = self._make_guard()
        # Manually set _integrity to a truthy value for the check
        guard._integrity = object()  # type: ignore[assignment]
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc71 = next(c for c in report.controls if c.control_id == "SOC2-CC7.1")
        assert cc71.status == "pass"

    def test_no_signing_fails_integrity_check(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc71 = next(c for c in report.controls if c.control_id == "SOC2-CC7.1")
        assert cc71.status == "fail"
        assert len(cc71.recommendations) > 0

    def test_self_protection_enabled_passes(self) -> None:
        guard = self._make_guard(self_protection=True)
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc81 = next(c for c in report.controls if c.control_id == "SOC2-CC8.1")
        assert cc81.status == "pass"

    def test_rate_limiting_present_passes(self) -> None:
        rules = [
            PolicyRule(
                name="rate-limited-search",
                tools=["web_search"],
                action="allow",
                rate_limit=RateLimit(max_calls=10, window="60s"),
            ),
        ]
        guard = self._make_guard(rules=rules)
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        cc63 = next(c for c in report.controls if c.control_id == "SOC2-CC6.3")
        assert cc63.status == "pass"

    def test_unknown_framework_raises(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        with pytest.raises(KeyError, match="Unknown framework"):
            assessor.assess("unknown")

    def test_human_in_the_loop_passes_with_require_approval(self) -> None:
        rules = [
            PolicyRule(
                name="approve-writes",
                tools=["file_write"],
                action="require_approval",
            ),
        ]
        guard = self._make_guard(rules=rules)
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("eu-ai-act")
        art14 = next(c for c in report.controls if c.control_id == "EU-AI-ACT-Art14")
        assert art14.status == "pass"

    def test_overall_compliant_when_all_pass(self) -> None:
        rules = [
            PolicyRule(
                name="approve-writes",
                tools=["file_write"],
                action="require_approval",
            ),
        ]
        guard = self._make_guard(rules=rules)
        # Set up logger and integrity to pass all checks
        guard._logger = object()  # type: ignore[assignment]
        guard._integrity = object()  # type: ignore[assignment]
        assessor = ComplianceAssessor(guard)
        # EU AI Act only checks: deny_by_default, audit_logging, human_in_the_loop
        report = assessor.assess("eu-ai-act")
        assert report.overall_status == "compliant"

    def test_summary_includes_framework_name(self) -> None:
        guard = self._make_guard()
        assessor = ComplianceAssessor(guard)
        report = assessor.assess("soc2")
        assert "soc2" in report.summary.lower() or "SOC" in report.summary
