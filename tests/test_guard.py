"""Tests for the Guard class, GuardSession, and EventBus."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from avakill.core.engine import Guard, GuardSession
from avakill.core.exceptions import ConfigError, PolicyViolation, RateLimitExceeded
from avakill.core.models import AuditEvent, PolicyConfig, PolicyRule, RateLimit
from avakill.logging.event_bus import EventBus


@pytest.fixture(autouse=True)
def _reset_event_bus():
    """Ensure each test gets a fresh EventBus singleton."""
    EventBus.reset()
    yield
    EventBus.reset()


@pytest.fixture
def rate_limit_policy() -> PolicyConfig:
    """Policy with a tight rate limit for testing."""
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(
                name="rate-limited-search",
                tools=["search"],
                action="allow",
                rate_limit=RateLimit(max_calls=2, window="60s"),
            ),
            PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
            PolicyRule(name="deny-delete", tools=["file_delete"], action="deny"),
        ],
    )


class TestGuardInit:
    """Tests for Guard initialisation."""

    def test_create_from_policy_config(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        assert guard.engine.config is sample_policy

    def test_create_from_yaml(self, tmp_policy_file: Path) -> None:
        guard = Guard(policy=tmp_policy_file)
        assert guard.engine.config.version == "1.0"

    def test_create_from_yaml_string(self, tmp_policy_file: Path) -> None:
        guard = Guard(policy=str(tmp_policy_file))
        assert guard.engine.config.version == "1.0"

    def test_create_from_dict(self) -> None:
        data = {
            "version": "1.0",
            "default_action": "allow",
            "policies": [
                {"name": "deny-all", "tools": ["*"], "action": "deny"},
            ],
        }
        guard = Guard(policy=data)
        assert guard.engine.config.default_action == "allow"

    def test_create_none_auto_detect(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy_file = tmp_path / "avakill.yaml"
        policy_file.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies:\n"
            "  - name: test\n    tools: ['*']\n    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)
        guard = Guard()
        assert guard.engine.config.default_action == "allow"

    def test_create_none_no_policy_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError, match="No policy file found"):
            Guard()

    def test_agent_id_stored(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, agent_id="my-agent")
        assert guard._agent_id == "my-agent"

    def test_self_protection_enabled_by_default(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        assert guard._self_protection is not None

    def test_self_protection_disabled(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, self_protection=False)
        assert guard._self_protection is None


class TestGuardEvaluate:
    """Tests for Guard.evaluate()."""

    def test_evaluate_allowed(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="file_read", args={"path": "/tmp/x"})
        assert decision.allowed is True
        assert decision.action == "allow"
        assert decision.policy_name == "allow-read"

    def test_evaluate_denied(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="file_delete", args={"path": "/etc/passwd"})
        assert decision.allowed is False
        assert decision.action == "deny"
        assert decision.policy_name == "deny-delete"

    def test_evaluate_require_approval(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="file_write", args={"path": "/tmp/x"})
        assert decision.allowed is False
        assert decision.action == "require_approval"

    def test_evaluate_default_deny(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="unknown_tool")
        assert decision.allowed is False
        assert decision.action == "deny"
        assert "default action" in (decision.reason or "").lower()

    def test_evaluate_no_args_defaults_to_empty(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="file_read")
        assert decision.allowed is True

    def test_evaluate_latency_populated(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate(tool="file_read")
        assert decision.latency_ms >= 0

    def test_evaluate_agent_id_fallback(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, agent_id="default-agent")
        # Just verify it runs without error with the default agent_id
        decision = guard.evaluate(tool="file_read")
        assert decision.allowed is True

    def test_evaluate_agent_id_override(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, agent_id="default-agent")
        decision = guard.evaluate(tool="file_read", agent_id="override-agent")
        assert decision.allowed is True

    def test_evaluate_rate_limit_exceeded(self, rate_limit_policy: PolicyConfig) -> None:
        guard = Guard(policy=rate_limit_policy)
        guard.evaluate(tool="search", args={"q": "a"})
        guard.evaluate(tool="search", args={"q": "b"})
        with pytest.raises(RateLimitExceeded):
            guard.evaluate(tool="search", args={"q": "c"})


class TestGuardEvaluateOrRaise:
    """Tests for Guard.evaluate_or_raise()."""

    def test_allowed_returns_decision(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        decision = guard.evaluate_or_raise(tool="file_read")
        assert decision.allowed is True

    def test_denied_raises_policy_violation(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with pytest.raises(PolicyViolation) as exc_info:
            guard.evaluate_or_raise(tool="file_delete")
        assert exc_info.value.tool_name == "file_delete"
        assert exc_info.value.decision.allowed is False

    def test_rate_limit_raises(self, rate_limit_policy: PolicyConfig) -> None:
        guard = Guard(policy=rate_limit_policy)
        guard.evaluate_or_raise(tool="search", args={"q": "a"})
        guard.evaluate_or_raise(tool="search", args={"q": "b"})
        with pytest.raises(RateLimitExceeded):
            guard.evaluate_or_raise(tool="search", args={"q": "c"})


class TestGuardSession:
    """Tests for Guard.session() and GuardSession."""

    def test_session_returns_context_manager(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        session = guard.session(agent_id="bot")
        assert isinstance(session, GuardSession)

    def test_session_auto_generates_session_id(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session(agent_id="bot") as s:
            assert s.session_id is not None
            # Should be a valid UUID
            UUID(s.session_id)

    def test_session_explicit_session_id(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session(session_id="my-session") as s:
            assert s.session_id == "my-session"

    def test_session_evaluate_delegates(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session(agent_id="bot") as s:
            decision = s.evaluate(tool="file_read")
            assert decision.allowed is True

    def test_session_evaluate_or_raise_delegates(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session() as s:
            decision = s.evaluate_or_raise(tool="file_read")
            assert decision.allowed is True

    def test_session_evaluate_or_raise_raises(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session() as s, pytest.raises(PolicyViolation):
            s.evaluate_or_raise(tool="file_delete")

    def test_session_tracks_call_count(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session() as s:
            assert s.call_count == 0
            s.evaluate(tool="file_read")
            assert s.call_count == 1
            s.evaluate(tool="file_read")
            assert s.call_count == 2

    def test_session_call_count_includes_raise(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        with guard.session() as s:
            s.evaluate_or_raise(tool="file_read")
            assert s.call_count == 1
            with pytest.raises(PolicyViolation):
                s.evaluate_or_raise(tool="file_delete")
            assert s.call_count == 2

    def test_session_inherits_guard_agent_id(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, agent_id="default")
        with guard.session() as s:
            assert s.agent_id == "default"

    def test_session_overrides_agent_id(self, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy, agent_id="default")
        with guard.session(agent_id="override") as s:
            assert s.agent_id == "override"


class TestGuardReloadPolicy:
    """Tests for Guard.reload_policy()."""

    def test_reload_from_path(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\npolicies:\n"
            "  - name: allow-read\n    tools: [file_read]\n    action: allow\n"
        )
        guard = Guard(policy=policy_file)
        assert guard.evaluate(tool="file_read").allowed is True
        assert guard.evaluate(tool="file_write").allowed is False

        # Rewrite policy to allow file_write too
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\npolicies:\n"
            "  - name: allow-read\n    tools: [file_read]\n    action: allow\n"
            "  - name: allow-write\n    tools: [file_write]\n    action: allow\n"
        )
        guard.reload_policy()
        assert guard.evaluate(tool="file_write").allowed is True

    def test_reload_from_explicit_path(self, tmp_path: Path, sample_policy: PolicyConfig) -> None:
        guard = Guard(policy=sample_policy)
        assert guard.evaluate(tool="unknown").allowed is False

        new_policy = tmp_path / "new.yaml"
        new_policy.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
        guard.reload_policy(new_policy)
        assert guard.evaluate(tool="unknown").allowed is True

    def test_reload_picks_up_changes(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "version: '1.0'\ndefault_action: deny\npolicies:\n"
            "  - name: deny-all\n    tools: ['*']\n    action: deny\n"
        )
        guard = Guard(policy=policy_file)
        assert guard.evaluate(tool="anything").allowed is False

        policy_file.write_text(
            "version: '1.0'\ndefault_action: allow\npolicies:\n"
            "  - name: allow-all\n    tools: ['*']\n    action: allow\n"
        )
        guard.reload_policy()
        assert guard.evaluate(tool="anything").allowed is True


class TestEventBus:
    """Tests for EventBus and its integration with Guard."""

    def test_singleton(self) -> None:
        bus1 = EventBus.get()
        bus2 = EventBus.get()
        assert bus1 is bus2

    def test_reset_creates_new_instance(self) -> None:
        bus1 = EventBus.get()
        EventBus.reset()
        bus2 = EventBus.get()
        assert bus1 is not bus2

    def test_subscribe_and_emit(self) -> None:
        bus = EventBus.get()
        received: list[AuditEvent] = []
        bus.subscribe(received.append)

        # Create a minimal event
        from avakill.core.models import Decision, ToolCall

        tc = ToolCall(tool_name="test", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)

        bus.emit(event)
        assert len(received) == 1
        assert received[0] is event

    def test_unsubscribe(self) -> None:
        bus = EventBus.get()
        received: list[AuditEvent] = []
        unsub = bus.subscribe(received.append)

        from avakill.core.models import Decision, ToolCall

        tc = ToolCall(tool_name="test", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)

        bus.emit(event)
        assert len(received) == 1

        unsub()
        bus.emit(event)
        assert len(received) == 1  # no new events

    def test_callback_exception_does_not_propagate(self) -> None:
        bus = EventBus.get()
        received: list[AuditEvent] = []

        def bad_callback(event: AuditEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(bad_callback)
        bus.subscribe(received.append)

        from avakill.core.models import Decision, ToolCall

        tc = ToolCall(tool_name="test", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)

        # Should not raise, and second subscriber should still receive
        bus.emit(event)
        assert len(received) == 1

    def test_guard_emits_events_on_evaluate(self, sample_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=sample_policy)
        guard.evaluate(tool="file_read")

        assert len(received) == 1
        assert received[0].tool_call.tool_name == "file_read"
        assert received[0].decision.allowed is True

    def test_guard_emits_events_on_deny(self, sample_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=sample_policy)
        guard.evaluate(tool="file_delete")

        assert len(received) == 1
        assert received[0].decision.allowed is False

    def test_guard_emits_events_on_rate_limit(self, rate_limit_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=rate_limit_policy)
        guard.evaluate(tool="search", args={"q": "a"})
        guard.evaluate(tool="search", args={"q": "b"})

        with pytest.raises(RateLimitExceeded):
            guard.evaluate(tool="search", args={"q": "c"})

        # All three calls should have emitted events
        assert len(received) == 3
        assert received[2].decision.allowed is False

    def test_multiple_subscribers_all_receive(self, sample_policy: PolicyConfig) -> None:
        received_a: list[AuditEvent] = []
        received_b: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received_a.append)
        bus.subscribe(received_b.append)

        guard = Guard(policy=sample_policy)
        guard.evaluate(tool="file_read")

        assert len(received_a) == 1
        assert len(received_b) == 1
