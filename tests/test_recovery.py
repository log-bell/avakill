"""Tests for recovery hints — mapping, exceptions, audit events, and CLI panel."""

from __future__ import annotations

import pytest
from rich.panel import Panel

from avakill.cli.recovery_panel import render_recovery_panel
from avakill.core.engine import Guard
from avakill.core.exceptions import PolicyViolation, RateLimitExceeded
from avakill.core.models import (
    AuditEvent,
    Decision,
    PolicyConfig,
    PolicyRule,
    RateLimit,
    ToolCall,
)
from avakill.core.recovery import RecoveryHint, recovery_hint_for
from avakill.logging.event_bus import EventBus


@pytest.fixture(autouse=True)
def _reset_event_bus():
    EventBus.reset()
    yield
    EventBus.reset()


# ------------------------------------------------------------------ #
# TestRecoveryHintFor — one test per denial source mapping
# ------------------------------------------------------------------ #


class TestRecoveryHintFor:
    """Tests for recovery_hint_for() pure function."""

    def test_allowed_returns_none(self) -> None:
        d = Decision(allowed=True, action="allow")
        assert recovery_hint_for(d) is None

    def test_self_protection_policy_write(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason="Self-protection: blocked file_write targeting policy file 'avakill.yaml'. Use .proposed.yaml for staging.",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "self-protection-policy-write"
        assert ".proposed.yaml" in hint.steps[0]

    def test_self_protection_shell_policy(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason="Self-protection: blocked shell command targeting policy file. Use .proposed.yaml for staging.",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "self-protection-policy-write"

    def test_self_protection_uninstall(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason="Self-protection: blocked attempt to uninstall avakill.",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "self-protection-uninstall"
        assert "human" in hint.steps[0].lower()

    def test_self_protection_approve(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason="Self-protection: blocked 'avakill approve' — only humans may activate policies.",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "self-protection-approve"

    def test_self_protection_source_mod(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason="Self-protection: blocked modification of avakill source files.",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "self-protection-source-mod"

    def test_rate_limit_exceeded(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="rate-limited-search",
            reason="Rate limit exceeded: 10 calls per 60s",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "rate-limit-exceeded"
        assert "rate-limited-search" in hint.summary

    def test_integrity_last_known_good(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="deny-delete",
            reason="Matched rule 'deny-delete'",
        )
        hint = recovery_hint_for(d, policy_status="last-known-good")
        assert hint is not None
        assert hint.source == "integrity-last-known-good"
        assert "sign" in hint.steps[0].lower()

    def test_integrity_deny_all(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            reason="No matching rule; default action is 'deny'",
        )
        hint = recovery_hint_for(d, policy_status="deny-all")
        assert hint is not None
        assert hint.source == "integrity-deny-all"
        assert "backup" in hint.steps[0].lower()

    def test_default_deny(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            reason="No matching rule; default action is 'deny'",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "default-deny"
        assert "allow" in hint.steps[0].lower()

    def test_policy_rule_deny(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="block-destructive-sql",
            reason="Matched rule 'block-destructive-sql'",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        assert hint.source == "policy-rule-deny"
        assert "block-destructive-sql" in hint.summary

    def test_hint_is_frozen(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="deny-all",
            reason="Matched rule 'deny-all'",
        )
        hint = recovery_hint_for(d)
        assert hint is not None
        with pytest.raises(Exception):
            hint.source = "something-else"  # type: ignore[misc]


# ------------------------------------------------------------------ #
# TestRecoveryOnExceptions — hints on PolicyViolation / RateLimitExceeded
# ------------------------------------------------------------------ #


class TestRecoveryOnExceptions:
    """Tests for recovery hints on exception objects."""

    def test_evaluate_or_raise_attaches_hint(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, self_protection=False)
        with pytest.raises(PolicyViolation) as exc_info:
            guard.evaluate_or_raise(tool="file_delete")
        exc = exc_info.value
        assert exc.recovery_hint is not None
        assert exc.recovery_hint.source == "policy-rule-deny"

    def test_rate_limit_exception_has_hint(self) -> None:
        policy = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(
                    name="rate-limited",
                    tools=["search"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=1, window="60s"),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)
        guard.evaluate(tool="search", args={"q": "a"})
        with pytest.raises(RateLimitExceeded) as exc_info:
            guard.evaluate(tool="search", args={"q": "b"})
        exc = exc_info.value
        assert exc.recovery_hint is not None
        assert exc.recovery_hint.source == "rate-limit-exceeded"

    def test_str_includes_hint_summary(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="deny-all",
            reason="Matched rule 'deny-all'",
        )
        hint = RecoveryHint(
            source="policy-rule-deny",
            summary="Denied by rule 'deny-all'",
            steps=("Review the rule.",),
        )
        exc = PolicyViolation("my_tool", d, recovery_hint=hint)
        s = str(exc)
        assert "[recovery: Denied by rule 'deny-all']" in s

    def test_str_without_hint_is_unchanged(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="deny-all",
            reason="Matched rule 'deny-all'",
        )
        exc = PolicyViolation("my_tool", d)
        s = str(exc)
        assert "[recovery:" not in s
        assert "AvaKill blocked 'my_tool'" in s

    def test_default_deny_evaluate_or_raise(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, self_protection=False)
        with pytest.raises(PolicyViolation) as exc_info:
            guard.evaluate_or_raise(tool="unknown_tool")
        exc = exc_info.value
        assert exc.recovery_hint is not None
        assert exc.recovery_hint.source == "default-deny"


# ------------------------------------------------------------------ #
# TestRecoveryOnAuditEvents — hints on AuditEvent via EventBus
# ------------------------------------------------------------------ #


class TestRecoveryOnAuditEvents:
    """Tests for recovery hints on audit events."""

    def test_denied_event_has_hint(self, sample_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=sample_policy, self_protection=False)
        guard.evaluate(tool="file_delete")

        assert len(received) == 1
        assert received[0].decision.allowed is False
        assert received[0].recovery_hint is not None
        assert received[0].recovery_hint.source == "policy-rule-deny"

    def test_allowed_event_has_no_hint(self, sample_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=sample_policy, self_protection=False)
        guard.evaluate(tool="file_read")

        assert len(received) == 1
        assert received[0].decision.allowed is True
        assert received[0].recovery_hint is None


# ------------------------------------------------------------------ #
# TestRecoveryPanel — Rich CLI panel rendering
# ------------------------------------------------------------------ #


class TestRecoveryPanel:
    """Tests for the Rich recovery panel renderer."""

    def test_render_returns_panel(self) -> None:
        hint = RecoveryHint(
            source="policy-rule-deny",
            summary="Denied by rule 'deny-all'",
            steps=("Review the rule.", "Add an allow rule."),
        )
        panel = render_recovery_panel(hint)
        assert isinstance(panel, Panel)

    def test_panel_content_includes_steps(self) -> None:
        hint = RecoveryHint(
            source="default-deny",
            summary="No matching rule",
            steps=("Add an allow rule.", "Set default_action: allow."),
        )
        panel = render_recovery_panel(hint, tool_name="my_tool")
        # The panel's renderable is a Text object; check its plain text
        plain = panel.renderable.plain  # type: ignore[union-attr]
        assert "my_tool" in plain
        assert "1. Add an allow rule." in plain
        assert "2. Set default_action: allow." in plain

    def test_panel_with_doc_url(self) -> None:
        hint = RecoveryHint(
            source="default-deny",
            summary="No matching rule",
            steps=("Add a rule.",),
            doc_url="https://avakill.dev/docs/recovery",
        )
        panel = render_recovery_panel(hint)
        plain = panel.renderable.plain  # type: ignore[union-attr]
        assert "https://avakill.dev/docs/recovery" in plain

    def test_panel_without_tool_name(self) -> None:
        hint = RecoveryHint(
            source="default-deny",
            summary="No matching rule",
            steps=("Step one.",),
        )
        panel = render_recovery_panel(hint)
        plain = panel.renderable.plain  # type: ignore[union-attr]
        assert "Tool:" not in plain
