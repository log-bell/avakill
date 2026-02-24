"""Comprehensive tests for AvaKill data models, exceptions, and policy engine."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from avakill.core.exceptions import (
    AvaKillError,
    ConfigError,
    PolicyViolation,
    RateLimitExceeded,
)
from avakill.core.models import (
    AuditEvent,
    Decision,
    PolicyConfig,
    PolicyRule,
    RateLimit,
    RuleConditions,
    ToolCall,
)
from avakill.core.policy import PolicyEngine, load_policy

# ---------------------------------------------------------------------------
# ToolCall
# ---------------------------------------------------------------------------


class TestToolCall:
    """Tests for the ToolCall model."""

    def test_minimal_creation(self) -> None:
        tc = ToolCall(tool_name="file_read", arguments={"path": "/tmp/x"})
        assert tc.tool_name == "file_read"
        assert tc.arguments == {"path": "/tmp/x"}
        assert tc.agent_id is None
        assert tc.session_id is None
        assert isinstance(tc.timestamp, datetime)
        assert tc.metadata == {}

    def test_full_creation(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"cmd": "ls"},
            agent_id="agent-1",
            session_id="sess-42",
            timestamp=ts,
            metadata={"env": "prod"},
        )
        assert tc.agent_id == "agent-1"
        assert tc.session_id == "sess-42"
        assert tc.timestamp == ts
        assert tc.metadata == {"env": "prod"}

    def test_serialize_roundtrip(self) -> None:
        tc = ToolCall(tool_name="web_search", arguments={"q": "test"})
        data = tc.model_dump()
        tc2 = ToolCall.model_validate(data)
        assert tc2.tool_name == tc.tool_name
        assert tc2.arguments == tc.arguments

    def test_json_roundtrip(self) -> None:
        tc = ToolCall(tool_name="db_query", arguments={"sql": "SELECT 1"})
        json_str = tc.model_dump_json()
        tc2 = ToolCall.model_validate_json(json_str)
        assert tc2.tool_name == tc.tool_name


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class TestDecision:
    """Tests for the Decision model."""

    def test_allowed_decision(self) -> None:
        d = Decision(allowed=True, action="allow")
        assert d.allowed is True
        assert d.action == "allow"
        assert d.policy_name is None
        assert d.reason is None
        assert d.latency_ms == 0.0

    def test_denied_decision_with_details(self) -> None:
        d = Decision(
            allowed=False,
            action="deny",
            policy_name="block-destructive-sql",
            reason="Destructive SQL operations require manual execution",
            latency_ms=1.5,
        )
        assert d.allowed is False
        assert d.policy_name == "block-destructive-sql"
        assert d.reason == "Destructive SQL operations require manual execution"
        assert d.latency_ms == 1.5

    def test_require_approval_action(self) -> None:
        d = Decision(allowed=False, action="require_approval")
        assert d.action == "require_approval"

    def test_invalid_action_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(allowed=True, action="maybe")

    def test_frozen_rejects_mutation(self) -> None:
        d = Decision(allowed=True, action="allow")
        with pytest.raises(ValidationError):
            d.allowed = False

    def test_serialize_roundtrip(self) -> None:
        d = Decision(allowed=False, action="deny", policy_name="test", latency_ms=2.0)
        data = d.model_dump()
        d2 = Decision.model_validate(data)
        assert d2.allowed == d.allowed
        assert d2.policy_name == d.policy_name

    def test_json_roundtrip(self) -> None:
        d = Decision(allowed=True, action="allow", reason="Allowed by default")
        json_str = d.model_dump_json()
        d2 = Decision.model_validate_json(json_str)
        assert d2.reason == "Allowed by default"


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------


class TestAuditEvent:
    """Tests for the AuditEvent model."""

    def test_creation(self) -> None:
        tc = ToolCall(tool_name="file_read", arguments={"path": "/tmp"})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)
        assert len(event.id) == 36  # UUID4 format
        assert event.tool_call.tool_name == "file_read"
        assert event.decision.allowed is True
        assert event.execution_result is None
        assert event.error is None

    def test_with_execution_result(self) -> None:
        tc = ToolCall(tool_name="file_read", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d, execution_result="file contents")
        assert event.execution_result == "file contents"

    def test_with_error(self) -> None:
        tc = ToolCall(tool_name="file_read", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d, error="File not found")
        assert event.error == "File not found"

    def test_frozen_rejects_mutation(self) -> None:
        tc = ToolCall(tool_name="file_read", arguments={})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)
        with pytest.raises(ValidationError):
            event.error = "oops"

    def test_unique_ids(self) -> None:
        tc = ToolCall(tool_name="test", arguments={})
        d = Decision(allowed=True, action="allow")
        e1 = AuditEvent(tool_call=tc, decision=d)
        e2 = AuditEvent(tool_call=tc, decision=d)
        assert e1.id != e2.id

    def test_serialize_roundtrip(self) -> None:
        tc = ToolCall(tool_name="web_search", arguments={"q": "hello"})
        d = Decision(allowed=False, action="deny", reason="blocked")
        event = AuditEvent(tool_call=tc, decision=d, error="denied")
        data = event.model_dump()
        event2 = AuditEvent.model_validate(data)
        assert event2.id == event.id
        assert event2.tool_call.tool_name == "web_search"
        assert event2.decision.reason == "blocked"
        assert event2.error == "denied"

    def test_json_roundtrip(self) -> None:
        tc = ToolCall(tool_name="test", arguments={"x": 1})
        d = Decision(allowed=True, action="allow")
        event = AuditEvent(tool_call=tc, decision=d)
        json_str = event.model_dump_json()
        event2 = AuditEvent.model_validate_json(json_str)
        assert event2.id == event.id


# ---------------------------------------------------------------------------
# RuleConditions
# ---------------------------------------------------------------------------


class TestRuleConditions:
    """Tests for the RuleConditions model."""

    def test_empty_conditions(self) -> None:
        rc = RuleConditions()
        assert rc.args_match is None
        assert rc.args_not_match is None

    def test_args_match(self) -> None:
        rc = RuleConditions(args_match={"sql": ["DROP", "DELETE"]})
        assert rc.args_match == {"sql": ["DROP", "DELETE"]}

    def test_args_not_match(self) -> None:
        rc = RuleConditions(args_not_match={"path": ["/etc", "/sys"]})
        assert rc.args_not_match == {"path": ["/etc", "/sys"]}

    def test_both_conditions(self) -> None:
        rc = RuleConditions(
            args_match={"cmd": ["git"]},
            args_not_match={"cmd": ["rm -rf"]},
        )
        assert rc.args_match is not None
        assert rc.args_not_match is not None

    def test_serialize_roundtrip(self) -> None:
        rc = RuleConditions(args_match={"query": ["SELECT"]})
        data = rc.model_dump()
        rc2 = RuleConditions.model_validate(data)
        assert rc2.args_match == rc.args_match


# ---------------------------------------------------------------------------
# RateLimit
# ---------------------------------------------------------------------------


class TestRateLimit:
    """Tests for the RateLimit model."""

    def test_valid_seconds(self) -> None:
        rl = RateLimit(max_calls=10, window="30s")
        assert rl.max_calls == 10
        assert rl.window == "30s"

    def test_valid_minutes(self) -> None:
        rl = RateLimit(max_calls=100, window="5m")
        assert rl.window == "5m"

    def test_valid_hours(self) -> None:
        rl = RateLimit(max_calls=1000, window="2h")
        assert rl.window == "2h"

    def test_window_seconds_30s(self) -> None:
        rl = RateLimit(max_calls=10, window="30s")
        assert rl.window_seconds() == 30

    def test_window_seconds_5m(self) -> None:
        rl = RateLimit(max_calls=100, window="5m")
        assert rl.window_seconds() == 300

    def test_window_seconds_2h(self) -> None:
        rl = RateLimit(max_calls=1000, window="2h")
        assert rl.window_seconds() == 7200

    def test_window_seconds_1s(self) -> None:
        rl = RateLimit(max_calls=1, window="1s")
        assert rl.window_seconds() == 1

    def test_window_seconds_1h(self) -> None:
        rl = RateLimit(max_calls=1, window="1h")
        assert rl.window_seconds() == 3600

    def test_invalid_window_no_unit(self) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch|Invalid window format"):
            RateLimit(max_calls=10, window="30")

    def test_invalid_window_bad_unit(self) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch|Invalid window format"):
            RateLimit(max_calls=10, window="30d")

    def test_invalid_window_empty(self) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch|Invalid window format"):
            RateLimit(max_calls=10, window="")

    def test_invalid_window_letters_only(self) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch|Invalid window format"):
            RateLimit(max_calls=10, window="abc")

    def test_invalid_window_negative(self) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch|Invalid window format"):
            RateLimit(max_calls=10, window="-5s")

    def test_serialize_roundtrip(self) -> None:
        rl = RateLimit(max_calls=50, window="10m")
        data = rl.model_dump()
        rl2 = RateLimit.model_validate(data)
        assert rl2.max_calls == 50
        assert rl2.window_seconds() == 600


# ---------------------------------------------------------------------------
# PolicyRule
# ---------------------------------------------------------------------------


class TestPolicyRule:
    """Tests for the PolicyRule model."""

    def test_minimal_creation(self) -> None:
        rule = PolicyRule(name="allow-reads", tools=["file_read"], action="allow")
        assert rule.name == "allow-reads"
        assert rule.tools == ["file_read"]
        assert rule.action == "allow"
        assert rule.conditions is None
        assert rule.rate_limit is None
        assert rule.message is None
        assert rule.log is True

    def test_full_creation(self) -> None:
        rule = PolicyRule(
            name="block-destructive-sql",
            tools=["database_*", "sql_execute"],
            action="deny",
            conditions=RuleConditions(args_not_match={"query": ["DROP", "TRUNCATE"]}),
            rate_limit=RateLimit(max_calls=10, window="1m"),
            message="Destructive SQL operations require manual execution",
            log=True,
        )
        assert len(rule.tools) == 2
        assert rule.conditions is not None
        assert rule.rate_limit is not None
        assert rule.rate_limit.window_seconds() == 60
        assert rule.message == "Destructive SQL operations require manual execution"

    def test_glob_pattern_in_tools(self) -> None:
        rule = PolicyRule(name="all-db", tools=["database_*"], action="deny")
        assert rule.tools == ["database_*"]

    def test_empty_tools_rejected(self) -> None:
        with pytest.raises(ValidationError, match="too_short|tools must have at least one entry"):
            PolicyRule(name="bad-rule", tools=[], action="allow")

    def test_invalid_action_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyRule(name="bad-action", tools=["test"], action="maybe")

    def test_require_approval_action(self) -> None:
        rule = PolicyRule(name="ask-first", tools=["deploy_*"], action="require_approval")
        assert rule.action == "require_approval"

    def test_serialize_roundtrip(self) -> None:
        rule = PolicyRule(
            name="test",
            tools=["a", "b"],
            action="deny",
            rate_limit=RateLimit(max_calls=5, window="1h"),
        )
        data = rule.model_dump()
        rule2 = PolicyRule.model_validate(data)
        assert rule2.name == "test"
        assert rule2.tools == ["a", "b"]
        assert rule2.rate_limit is not None
        assert rule2.rate_limit.window_seconds() == 3600

    def test_json_roundtrip(self) -> None:
        rule = PolicyRule(name="test", tools=["x"], action="allow", message="ok")
        json_str = rule.model_dump_json()
        rule2 = PolicyRule.model_validate_json(json_str)
        assert rule2.message == "ok"


# ---------------------------------------------------------------------------
# PolicyConfig
# ---------------------------------------------------------------------------


class TestPolicyConfig:
    """Tests for the PolicyConfig model."""

    def test_minimal_creation(self) -> None:
        config = PolicyConfig(policies=[PolicyRule(name="r1", tools=["t1"], action="allow")])
        assert config.version == "1.0"
        assert config.default_action == "deny"
        assert len(config.policies) == 1
        assert config.notifications == {}

    def test_full_creation(self) -> None:
        config = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="block-deletes", tools=["file_delete"], action="deny"),
                PolicyRule(name="allow-reads", tools=["file_read"], action="allow"),
            ],
            notifications={"slack": {"webhook": "https://hooks.slack.com/xxx"}},
        )
        assert config.default_action == "allow"
        assert len(config.policies) == 2
        assert "slack" in config.notifications

    def test_version_must_be_1_0(self) -> None:
        with pytest.raises(ValidationError, match="only '1.0' is supported"):
            PolicyConfig(
                version="2.0",
                policies=[PolicyRule(name="r", tools=["t"], action="allow")],
            )

    def test_invalid_default_action(self) -> None:
        with pytest.raises(ValidationError):
            PolicyConfig(
                default_action="maybe",
                policies=[PolicyRule(name="r", tools=["t"], action="allow")],
            )

    def test_serialize_roundtrip(self) -> None:
        config = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="limit-api",
                    tools=["api_call"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=100, window="1h"),
                ),
            ],
        )
        data = config.model_dump()
        config2 = PolicyConfig.model_validate(data)
        assert config2.default_action == "allow"
        assert config2.policies[0].rate_limit is not None
        assert config2.policies[0].rate_limit.window_seconds() == 3600

    def test_json_roundtrip(self) -> None:
        config = PolicyConfig(policies=[PolicyRule(name="r", tools=["t"], action="deny")])
        json_str = config.model_dump_json()
        config2 = PolicyConfig.model_validate_json(json_str)
        assert config2.version == "1.0"
        assert len(config2.policies) == 1


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TestPolicyViolation:
    """Tests for the PolicyViolation exception."""

    def test_str_with_policy_name(self) -> None:
        decision = Decision(
            allowed=False,
            action="deny",
            policy_name="block-destructive-sql",
            reason="Destructive SQL operations require manual execution",
        )
        exc = PolicyViolation("delete_user", decision)
        result = str(exc)
        assert result == (
            "AvaKill blocked 'delete_user': "
            "Destructive SQL operations require manual execution "
            "[policy: block-destructive-sql]"
        )

    def test_str_without_policy_name(self) -> None:
        decision = Decision(
            allowed=False,
            action="deny",
            reason="Not allowed",
        )
        exc = PolicyViolation("shell_exec", decision)
        result = str(exc)
        assert result == "AvaKill blocked 'shell_exec': Not allowed"
        assert "[policy:" not in result

    def test_str_with_custom_message(self) -> None:
        decision = Decision(allowed=False, action="deny", policy_name="p1")
        exc = PolicyViolation("tool_x", decision, message="Custom reason")
        result = str(exc)
        assert "Custom reason" in result
        assert "[policy: p1]" in result

    def test_str_fallback_to_default_message(self) -> None:
        decision = Decision(allowed=False, action="deny")
        exc = PolicyViolation("tool_y", decision)
        assert "Policy violation" in str(exc)

    def test_attributes(self) -> None:
        decision = Decision(
            allowed=False,
            action="deny",
            reason="blocked",
            policy_name="rule-1",
        )
        exc = PolicyViolation("my_tool", decision)
        assert exc.tool_name == "my_tool"
        assert exc.decision is decision
        assert exc.message == "blocked"

    def test_is_agent_guard_error(self) -> None:
        decision = Decision(allowed=False, action="deny")
        exc = PolicyViolation("t", decision)
        assert isinstance(exc, AvaKillError)
        assert isinstance(exc, Exception)

    def test_can_be_caught_as_exception(self) -> None:
        decision = Decision(allowed=False, action="deny", reason="no")
        with pytest.raises(PolicyViolation):
            raise PolicyViolation("tool", decision)


class TestConfigError:
    """Tests for the ConfigError exception."""

    def test_message(self) -> None:
        exc = ConfigError("bad yaml")
        assert exc.message == "bad yaml"
        assert str(exc) == "bad yaml"

    def test_is_agent_guard_error(self) -> None:
        exc = ConfigError("err")
        assert isinstance(exc, AvaKillError)


class TestRateLimitExceeded:
    """Tests for the RateLimitExceeded exception."""

    def test_is_policy_violation(self) -> None:
        decision = Decision(
            allowed=False,
            action="deny",
            policy_name="rate-limit-api",
            reason="Rate limit exceeded: 10 calls per 60s",
        )
        exc = RateLimitExceeded("api_call", decision)
        assert isinstance(exc, PolicyViolation)
        assert isinstance(exc, AvaKillError)
        assert "rate-limit-api" in str(exc)

    def test_can_be_caught_as_policy_violation(self) -> None:
        decision = Decision(allowed=False, action="deny", reason="limit hit")
        with pytest.raises(PolicyViolation):
            raise RateLimitExceeded("tool", decision)


# ---------------------------------------------------------------------------
# PolicyEngine — loading
# ---------------------------------------------------------------------------


class TestPolicyEngineLoading:
    """Tests for PolicyEngine construction from YAML, dict, and string."""

    def test_from_yaml(self, tmp_policy_file: Path) -> None:
        engine = PolicyEngine.from_yaml(tmp_policy_file)
        assert engine.config.default_action == "deny"
        assert len(engine.config.policies) == 1
        assert engine.config.policies[0].name == "allow-read"

    def test_from_yaml_missing_file(self) -> None:
        with pytest.raises(ConfigError, match="not found"):
            PolicyEngine.from_yaml("/nonexistent/path.yaml")

    def test_from_dict(self) -> None:
        data = {
            "version": "1.0",
            "default_action": "allow",
            "policies": [
                {"name": "r1", "tools": ["file_read"], "action": "allow"},
            ],
        }
        engine = PolicyEngine.from_dict(data)
        assert engine.config.default_action == "allow"
        assert engine.config.policies[0].name == "r1"

    def test_from_dict_invalid_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="Invalid policy"):
            PolicyEngine.from_dict({"version": "99.0", "policies": []})

    def test_from_string(self) -> None:
        yaml_str = (
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: r1\n"
            "    tools: [test_tool]\n"
            "    action: allow\n"
        )
        engine = PolicyEngine.from_string(yaml_str)
        assert engine.config.policies[0].tools == ["test_tool"]

    def test_from_string_invalid_yaml(self) -> None:
        with pytest.raises(ConfigError, match="Invalid YAML"):
            PolicyEngine.from_string(":\n  - :\n    bad: [")

    def test_from_string_non_mapping(self) -> None:
        with pytest.raises(ConfigError, match="mapping"):
            PolicyEngine.from_string("- just\n- a\n- list\n")

    def test_from_string_empty_is_valid(self) -> None:
        # Empty YAML yields {}, which needs policies — should raise ConfigError
        with pytest.raises(ConfigError, match="Invalid policy"):
            PolicyEngine.from_string("")

    def test_env_var_substitution(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "env_policy.yaml"
        policy_file.write_text(
            "version: '1.0'\n"
            "default_action: ${TEST_AG_DEFAULT}\n"
            "policies:\n"
            "  - name: r1\n"
            "    tools: [t1]\n"
            "    action: allow\n"
        )
        with patch.dict("os.environ", {"TEST_AG_DEFAULT": "allow"}):
            engine = PolicyEngine.from_yaml(policy_file)
        assert engine.config.default_action == "allow"

    def test_env_var_unset_kept_as_is(self, tmp_path: Path) -> None:
        yaml_str = (
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: r1\n"
            "    tools: [t1]\n"
            "    action: allow\n"
            "    message: '${UNSET_VAR_XYZ}'\n"
        )
        with patch.dict("os.environ", {}, clear=False):
            # Remove the var if it happens to exist
            import os

            os.environ.pop("UNSET_VAR_XYZ", None)
            engine = PolicyEngine.from_string(yaml_str)
        assert engine.config.policies[0].message == "${UNSET_VAR_XYZ}"

    def test_load_templates(self) -> None:
        """Verify all three bundled templates parse correctly."""
        templates_dir = Path(__file__).resolve().parent.parent / "src" / "avakill" / "templates"
        for name in ("default.yaml", "strict.yaml", "permissive.yaml"):
            engine = PolicyEngine.from_yaml(templates_dir / name)
            assert len(engine.config.policies) > 0


# ---------------------------------------------------------------------------
# PolicyEngine — tool matching
# ---------------------------------------------------------------------------


class TestPolicyEngineToolMatching:
    """Tests for tool name pattern matching."""

    def _engine(self, tools: list[str], action: str = "allow") -> PolicyEngine:
        return PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[PolicyRule(name="r", tools=tools, action=action)],
            )
        )

    def test_exact_match(self) -> None:
        engine = self._engine(["database_query"])
        tc = ToolCall(tool_name="database_query", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is True

    def test_exact_no_match(self) -> None:
        engine = self._engine(["database_query"])
        tc = ToolCall(tool_name="file_read", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is False  # falls to default deny

    def test_glob_prefix(self) -> None:
        engine = self._engine(["database_*"])
        for name in ("database_query", "database_insert", "database_delete"):
            tc = ToolCall(tool_name=name, arguments={})
            assert engine.evaluate(tc).allowed is True

    def test_glob_suffix(self) -> None:
        engine = self._engine(["*_execute"])
        tc = ToolCall(tool_name="shell_execute", arguments={})
        assert engine.evaluate(tc).allowed is True
        tc2 = ToolCall(tool_name="code_execute", arguments={})
        assert engine.evaluate(tc2).allowed is True

    def test_glob_no_match(self) -> None:
        engine = self._engine(["database_*"])
        tc = ToolCall(tool_name="file_read", arguments={})
        assert engine.evaluate(tc).allowed is False

    def test_star_matches_everything(self) -> None:
        engine = self._engine(["*"])
        tc = ToolCall(tool_name="anything_at_all", arguments={})
        assert engine.evaluate(tc).allowed is True

    def test_all_matches_everything(self) -> None:
        engine = self._engine(["all"])
        tc = ToolCall(tool_name="literally_anything", arguments={})
        assert engine.evaluate(tc).allowed is True

    def test_multiple_patterns(self) -> None:
        engine = self._engine(["file_read", "web_search"])
        assert engine.evaluate(ToolCall(tool_name="file_read", arguments={})).allowed
        assert engine.evaluate(ToolCall(tool_name="web_search", arguments={})).allowed
        assert not engine.evaluate(ToolCall(tool_name="file_write", arguments={})).allowed


# ---------------------------------------------------------------------------
# PolicyEngine — conditions
# ---------------------------------------------------------------------------


class TestPolicyEngineConditions:
    """Tests for args_match and args_not_match conditions."""

    def test_args_match_passes(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="select-only",
                        tools=["database_query"],
                        action="allow",
                        conditions=RuleConditions(args_match={"query": ["SELECT"]}),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="database_query", arguments={"query": "SELECT * FROM users"})
        assert engine.evaluate(tc).allowed is True

    def test_args_match_case_insensitive(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="r",
                        tools=["db"],
                        action="allow",
                        conditions=RuleConditions(args_match={"q": ["select"]}),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="db", arguments={"q": "SELECT * FROM t"})
        assert engine.evaluate(tc).allowed is True

    def test_args_match_fails_skips_rule(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="select-only",
                        tools=["database_query"],
                        action="allow",
                        conditions=RuleConditions(args_match={"query": ["SELECT"]}),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="database_query", arguments={"query": "DROP TABLE users"})
        # Rule doesn't match due to conditions, falls to default deny
        assert engine.evaluate(tc).allowed is False

    def test_args_match_missing_arg(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="r",
                        tools=["t"],
                        action="allow",
                        conditions=RuleConditions(args_match={"missing_key": ["x"]}),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="t", arguments={})
        assert engine.evaluate(tc).allowed is False

    def test_args_not_match_skips_rule_when_matched(self) -> None:
        """args_not_match: if bad substring found → condition fails → rule skipped."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="safe-queries-only",
                        tools=["database_query"],
                        action="allow",
                        conditions=RuleConditions(args_not_match={"query": ["DROP", "TRUNCATE"]}),
                    ),
                ],
            )
        )
        # Query contains "DROP" → args_not_match fails → rule skipped → default allow
        tc_bad = ToolCall(tool_name="database_query", arguments={"query": "DROP TABLE users"})
        assert engine.evaluate(tc_bad).allowed is True  # fell through to default

        # Query is safe → args_not_match passes → rule matches → allow
        tc_safe = ToolCall(tool_name="database_query", arguments={"query": "SELECT 1"})
        d = engine.evaluate(tc_safe)
        assert d.allowed is True
        assert d.policy_name == "safe-queries-only"

    def test_args_match_on_deny_blocks_dangerous(self) -> None:
        """Use args_match on a deny rule to block dangerous patterns."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-drop",
                        tools=["database_query"],
                        action="deny",
                        conditions=RuleConditions(args_match={"query": ["DROP", "TRUNCATE"]}),
                    ),
                ],
            )
        )
        # Contains DROP → args_match passes → rule matches → deny
        tc_bad = ToolCall(tool_name="database_query", arguments={"query": "DROP TABLE users"})
        assert engine.evaluate(tc_bad).allowed is False

        # Safe query → args_match fails → rule skipped → default allow
        tc_safe = ToolCall(tool_name="database_query", arguments={"query": "SELECT 1"})
        assert engine.evaluate(tc_safe).allowed is True

    def test_multiple_args_match_keys_and_logic(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="r",
                        tools=["api"],
                        action="allow",
                        conditions=RuleConditions(
                            args_match={"method": ["GET"], "path": ["/api/"]}
                        ),
                    ),
                ],
            )
        )
        # Both match
        tc1 = ToolCall(tool_name="api", arguments={"method": "GET", "path": "/api/users"})
        assert engine.evaluate(tc1).allowed is True
        # Only one matches
        tc2 = ToolCall(tool_name="api", arguments={"method": "POST", "path": "/api/users"})
        assert engine.evaluate(tc2).allowed is False
        # Neither matches
        tc3 = ToolCall(tool_name="api", arguments={"method": "POST", "path": "/admin"})
        assert engine.evaluate(tc3).allowed is False


# ---------------------------------------------------------------------------
# PolicyEngine — first-match-wins and default action
# ---------------------------------------------------------------------------


class TestPolicyEngineOrdering:
    """Tests for first-match-wins and default_action behavior."""

    def test_first_match_wins(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(name="deny-first", tools=["file_read"], action="deny"),
                    PolicyRule(name="allow-second", tools=["file_read"], action="allow"),
                ],
            )
        )
        tc = ToolCall(tool_name="file_read", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is False
        assert decision.policy_name == "deny-first"

    def test_second_rule_matches_when_first_does_not(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(name="r1", tools=["file_write"], action="deny"),
                    PolicyRule(name="r2", tools=["file_read"], action="allow"),
                ],
            )
        )
        tc = ToolCall(tool_name="file_read", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is True
        assert decision.policy_name == "r2"

    def test_default_action_deny(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(name="r1", tools=["file_read"], action="allow"),
                ],
            )
        )
        tc = ToolCall(tool_name="unknown_tool", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is False
        assert decision.action == "deny"
        assert "default action" in decision.reason

    def test_default_action_allow(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(name="r1", tools=["file_delete"], action="deny"),
                ],
            )
        )
        tc = ToolCall(tool_name="unknown_tool", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is True
        assert decision.action == "allow"

    def test_require_approval_not_allowed(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="ask",
                        tools=["email_send"],
                        action="require_approval",
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="email_send", arguments={})
        decision = engine.evaluate(tc)
        assert decision.allowed is False
        assert decision.action == "require_approval"

    def test_custom_message_in_decision(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="r1",
                        tools=["t"],
                        action="deny",
                        message="Custom deny message",
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="t", arguments={})
        decision = engine.evaluate(tc)
        assert decision.reason == "Custom deny message"

    def test_latency_populated(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[PolicyRule(name="r", tools=["t"], action="allow")],
            )
        )
        tc = ToolCall(tool_name="t", arguments={})
        decision = engine.evaluate(tc)
        assert decision.latency_ms >= 0.0


# ---------------------------------------------------------------------------
# PolicyEngine — rate limiting
# ---------------------------------------------------------------------------


class TestPolicyEngineRateLimit:
    """Tests for rate limiting."""

    def test_within_rate_limit(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["api_call"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=3, window="60s"),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="api_call", arguments={})
        for _ in range(3):
            decision = engine.evaluate(tc)
            assert decision.allowed is True

    def test_exceeds_rate_limit(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["api_call"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=2, window="60s"),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="api_call", arguments={})
        engine.evaluate(tc)
        engine.evaluate(tc)
        with pytest.raises(RateLimitExceeded) as exc_info:
            engine.evaluate(tc)
        assert "Rate limit exceeded" in str(exc_info.value)
        assert exc_info.value.decision.policy_name == "limited"

    def test_rate_limit_window_expires(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["api_call"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=1, window="1s"),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="api_call", arguments={})
        engine.evaluate(tc)

        # Simulate time passing by manipulating the stored timestamps
        with engine._lock:
            timestamps = engine._rate_limit_windows["api_call"]
            # Move the timestamp 2 seconds into the past
            timestamps[0] -= 2.0

        # Should succeed now because the old entry expired
        decision = engine.evaluate(tc)
        assert decision.allowed is True

    def test_rate_limit_per_tool_name(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["*"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=1, window="60s"),
                    ),
                ],
            )
        )
        # Different tool names have separate counters
        engine.evaluate(ToolCall(tool_name="tool_a", arguments={}))
        engine.evaluate(ToolCall(tool_name="tool_b", arguments={}))
        # Both should be fine, but calling tool_a again should fail
        with pytest.raises(RateLimitExceeded):
            engine.evaluate(ToolCall(tool_name="tool_a", arguments={}))

    def test_rate_limit_caught_as_policy_violation(self) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["t"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=1, window="60s"),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="t", arguments={})
        engine.evaluate(tc)
        with pytest.raises(PolicyViolation):
            engine.evaluate(tc)

    def test_rate_limit_per_agent(self) -> None:
        """Agent A's exhausted quota should not block Agent B."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["api_call"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=1, window="60s"),
                    ),
                ],
            )
        )
        # Agent A exhausts its quota
        tc_a = ToolCall(tool_name="api_call", arguments={}, agent_id="agent-a")
        engine.evaluate(tc_a)
        with pytest.raises(RateLimitExceeded):
            engine.evaluate(tc_a)

        # Agent B should still be allowed
        tc_b = ToolCall(tool_name="api_call", arguments={}, agent_id="agent-b")
        decision = engine.evaluate(tc_b)
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# PolicyEngine — conditions + tool matching integration
# ---------------------------------------------------------------------------


class TestPolicyEngineIntegration:
    """Integration tests combining conditions, globs, ordering, and rate limits."""

    def test_condition_skips_to_next_rule(self) -> None:
        """When conditions don't match, the engine should try the next rule."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-select",
                        tools=["database_query"],
                        action="allow",
                        conditions=RuleConditions(args_match={"query": ["SELECT"]}),
                    ),
                    PolicyRule(
                        name="deny-other-db",
                        tools=["database_query"],
                        action="deny",
                        message="Non-SELECT queries are denied",
                    ),
                ],
            )
        )
        # SELECT → first rule matches → allowed
        tc1 = ToolCall(tool_name="database_query", arguments={"query": "SELECT * FROM t"})
        assert engine.evaluate(tc1).allowed is True
        assert engine.evaluate(tc1).policy_name == "allow-select"

        # INSERT → first rule skipped → second rule matches → denied
        tc2 = ToolCall(tool_name="database_query", arguments={"query": "INSERT INTO t VALUES(1)"})
        d2 = engine.evaluate(tc2)
        assert d2.allowed is False
        assert d2.policy_name == "deny-other-db"

    def test_glob_with_args_match_deny(self) -> None:
        """Use args_match on a deny rule with glob tools to block dangerous commands."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-dangerous-shell",
                        tools=["shell_*"],
                        action="deny",
                        conditions=RuleConditions(args_match={"cmd": ["rm -rf", "sudo"]}),
                    ),
                ],
            )
        )
        # Dangerous command: "sudo rm -rf /" contains "rm -rf" → args_match passes → deny
        tc_bad = ToolCall(tool_name="shell_exec", arguments={"cmd": "sudo rm -rf /"})
        assert engine.evaluate(tc_bad).allowed is False

        # Safe command: no dangerous strings → args_match fails → default allow
        tc_safe = ToolCall(tool_name="shell_exec", arguments={"cmd": "ls -la"})
        assert engine.evaluate(tc_safe).allowed is True

    def test_glob_with_args_not_match_allowlist(self) -> None:
        """Use args_not_match on an allow rule to exclude dangerous patterns from allowlisting."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-safe-shell",
                        tools=["shell_*"],
                        action="allow",
                        conditions=RuleConditions(args_not_match={"cmd": ["rm -rf", "sudo"]}),
                    ),
                ],
            )
        )
        # Safe command: no bad substrings → args_not_match passes → rule matches → allow
        tc_safe = ToolCall(tool_name="shell_exec", arguments={"cmd": "ls -la"})
        assert engine.evaluate(tc_safe).allowed is True

        # Dangerous: contains "sudo" → args_not_match fails → rule skipped → default deny
        tc_bad = ToolCall(tool_name="shell_exec", arguments={"cmd": "sudo reboot"})
        assert engine.evaluate(tc_bad).allowed is False


# ---------------------------------------------------------------------------
# PolicyEngine — shell_safe condition
# ---------------------------------------------------------------------------


class TestPolicyEngineShellSafe:
    """Tests for the shell_safe condition on policy rules."""

    def _engine_with_shell_safe(self) -> PolicyEngine:
        """Engine with a shell_safe allow rule + catch-all deny."""
        return PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-safe-shell",
                        tools=["shell_*"],
                        action="allow",
                        conditions=RuleConditions(shell_safe=True),
                    ),
                ],
            )
        )

    def test_clean_command_allowed(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo hello"})
        assert engine.evaluate(tc).allowed is True

    def test_ls_allowed(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "ls -la"})
        assert engine.evaluate(tc).allowed is True

    def test_pipe_rejected(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "cat file | sh"})
        d = engine.evaluate(tc)
        assert d.allowed is False

    def test_redirect_rejected(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo data > file.txt"})
        assert engine.evaluate(tc).allowed is False

    def test_semicolon_rejected(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo a; rm -rf /"})
        assert engine.evaluate(tc).allowed is False

    def test_subshell_rejected(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo $(whoami)"})
        assert engine.evaluate(tc).allowed is False

    def test_backtick_rejected(self) -> None:
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo `id`"})
        assert engine.evaluate(tc).allowed is False

    def test_fallthrough_to_default_deny(self) -> None:
        """Metachar command skips allow rule, hits default deny."""
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo foo > bar"})
        d = engine.evaluate(tc)
        assert d.allowed is False
        assert d.policy_name is None  # fell through to default

    def test_cmd_arg_key_works(self) -> None:
        """shell_safe checks both 'command' and 'cmd' argument keys."""
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "echo data > file"})
        assert engine.evaluate(tc).allowed is False

    def test_default_false_ignores_metachars(self) -> None:
        """When shell_safe is False (default), metachars are not checked."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-all-shell",
                        tools=["shell_*"],
                        action="allow",
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="shell_exec", arguments={"command": "echo foo > bar"})
        assert engine.evaluate(tc).allowed is True

    def test_combined_with_args_match(self) -> None:
        """shell_safe + args_match both must pass."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-echo-safe",
                        tools=["shell_exec"],
                        action="allow",
                        conditions=RuleConditions(
                            shell_safe=True,
                            args_match={"command": ["echo"]},
                        ),
                    ),
                ],
            )
        )
        # echo without metachars → both pass → allowed
        tc_good = ToolCall(tool_name="shell_exec", arguments={"command": "echo hello"})
        assert engine.evaluate(tc_good).allowed is True

        # echo with redirect → shell_safe fails → denied
        tc_redir = ToolCall(
            tool_name="shell_exec", arguments={"command": "echo payload > target.txt"}
        )
        assert engine.evaluate(tc_redir).allowed is False

        # ls without metachars → args_match fails (no "echo") → denied
        tc_ls = ToolCall(tool_name="shell_exec", arguments={"command": "ls -la"})
        assert engine.evaluate(tc_ls).allowed is False

    def test_empty_command_passes(self) -> None:
        """Empty command string is considered safe."""
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"command": ""})
        # Empty command → shell_safe passes → but args_match not set → allowed
        assert engine.evaluate(tc).allowed is True

    def test_no_command_arg_passes(self) -> None:
        """Missing command/cmd argument is treated as empty → safe."""
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="shell_exec", arguments={"path": "/tmp"})
        assert engine.evaluate(tc).allowed is True

    def test_unrelated_tool_unaffected(self) -> None:
        """shell_safe rule only applies to shell_* tools."""
        engine = self._engine_with_shell_safe()
        tc = ToolCall(tool_name="file_read", arguments={"path": "test.txt"})
        # file_read doesn't match shell_* → falls to default deny
        assert engine.evaluate(tc).allowed is False


# ---------------------------------------------------------------------------
# PolicyEngine — default template rate limit ordering (Bug 3)
# ---------------------------------------------------------------------------


class TestDefaultTemplateRateLimit:
    """Bug 3: Verify rate-limit rules fire before broad allow rules in default.yaml."""

    def test_default_template_rate_limits_web_search(self) -> None:
        """Load default.yaml and verify web_search hits rate-limit, not allow-read-operations."""
        templates_dir = Path(__file__).resolve().parent.parent / "src" / "avakill" / "templates"
        engine = PolicyEngine.from_yaml(templates_dir / "default.yaml")

        tc = ToolCall(tool_name="web_search", arguments={"query": "test"})

        # First call should be allowed by rate-limit rule (not allow-read-operations)
        decision = engine.evaluate(tc)
        assert decision.allowed is True
        assert decision.policy_name == "rate-limit-web-search"

        # Exhaust the rate limit (30 calls total, 1 already done)
        for _ in range(29):
            engine.evaluate(tc)

        # 31st call should trigger rate limit
        with pytest.raises(RateLimitExceeded):
            engine.evaluate(tc)


# ---------------------------------------------------------------------------
# load_policy convenience function
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    """Tests for the load_policy convenience function."""

    def test_load_with_explicit_path(self, tmp_policy_file: Path) -> None:
        engine = load_policy(tmp_policy_file)
        assert engine.config.default_action == "deny"

    def test_load_auto_detect(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy_file = tmp_path / "avakill.yaml"
        policy_file.write_text(
            "version: '1.0'\n"
            "default_action: allow\n"
            "policies:\n"
            "  - name: r\n"
            "    tools: [t]\n"
            "    action: allow\n"
        )
        monkeypatch.chdir(tmp_path)
        engine = load_policy()
        assert engine.config.default_action == "allow"

    def test_load_auto_detect_yml_extension(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_file = tmp_path / "avakill.yml"
        policy_file.write_text(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: r\n"
            "    tools: [t]\n"
            "    action: deny\n"
        )
        monkeypatch.chdir(tmp_path)
        engine = load_policy()
        assert engine.config.default_action == "deny"

    def test_load_no_file_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError, match="No policy file found"):
            load_policy()


# ---------------------------------------------------------------------------
# command_allowlist condition
# ---------------------------------------------------------------------------


class TestPolicyEngineCommandAllowlist:
    """Tests for the command_allowlist condition."""

    def _engine(self) -> PolicyEngine:
        return PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="allow-safe-commands",
                        tools=["shell_execute"],
                        action="allow",
                        conditions=RuleConditions(
                            shell_safe=True,
                            command_allowlist=["echo", "ls", "git", "cat", "pip"],
                        ),
                    ),
                    PolicyRule(
                        name="deny-all",
                        tools=["*"],
                        action="deny",
                    ),
                ],
            )
        )

    def test_allowed_command_passes(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": "echo hello"})
        assert engine.evaluate(tc).allowed

    def test_allowed_command_with_flags(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": "ls -la"})
        assert engine.evaluate(tc).allowed

    def test_git_subcommand_allowed(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": "git status"})
        assert engine.evaluate(tc).allowed

    def test_env_prefix_bypass_blocked(self) -> None:
        """Attack #30: env VAR=val echo should be denied."""
        engine = self._engine()
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"command": "env AVAKILL_POLICY=/dev/null echo bypassed"},
        )
        assert not engine.evaluate(tc).allowed

    def test_unknown_command_denied(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": "rm -rf /"})
        assert not engine.evaluate(tc).allowed

    def test_empty_command_denied(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": ""})
        assert not engine.evaluate(tc).allowed

    def test_case_insensitive(self) -> None:
        engine = self._engine()
        tc = ToolCall(tool_name="shell_execute", arguments={"command": "ECHO hello"})
        assert engine.evaluate(tc).allowed

    def test_combined_with_shell_safe_blocks_metachar(self) -> None:
        engine = self._engine()
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"command": "echo hello | sh"},
        )
        assert not engine.evaluate(tc).allowed

    def test_sudo_prefix_blocked(self) -> None:
        engine = self._engine()
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"command": "sudo echo hello"},
        )
        assert not engine.evaluate(tc).allowed

    def test_pip_list_allowed(self) -> None:
        engine = self._engine()
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"command": "pip list"},
        )
        assert engine.evaluate(tc).allowed

    def test_pip_uninstall_blocked_by_self_protection_not_allowlist(self) -> None:
        """pip is in allowlist but uninstall is caught by self-protection."""
        engine = self._engine()
        tc = ToolCall(
            tool_name="shell_execute",
            arguments={"command": "pip uninstall avakill"},
        )
        # command_allowlist allows "pip" as first token, but shell_safe passes
        # (no metacharacters). This would be allowed by the policy engine alone.
        # Self-protection catches it at a higher layer.
        assert engine.evaluate(tc).allowed


# ---------------------------------------------------------------------------
# PolicyEngine — path_match / path_not_match conditions (T2)
# ---------------------------------------------------------------------------


class TestPolicyEnginePathMatch:
    """Tests for the T2 path_match and path_not_match conditions."""

    def test_tilde_catches_rm_rf_home(self) -> None:
        """rm -rf ~/ is denied by path_match on command targeting ~/."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-home-delete",
                        tools=["shell_*", "Bash"],
                        action="deny",
                        conditions=RuleConditions(
                            args_match={"command": ["rm -rf", "rm -r"]},
                            path_match={"command": ["~/"]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="Bash", arguments={"command": "rm -rf ~/"})
        assert engine.evaluate(tc).allowed is False

    def test_env_var_expansion(self) -> None:
        """rm -rf $HOME/Downloads is denied."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-home-delete",
                        tools=["shell_*", "Bash"],
                        action="deny",
                        conditions=RuleConditions(
                            args_match={"command": ["rm -rf"]},
                            path_match={"command": ["~/"]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(
            tool_name="Bash",
            arguments={"command": "rm -rf $HOME/Downloads"},
        )
        assert engine.evaluate(tc).allowed is False

    def test_dotdot_resolution(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """../ resolves to ancestor — a path traversal into a protected dir is caught."""
        # Create structure: tmp_path/protected/secret.txt and tmp_path/work/
        protected = tmp_path / "protected"
        protected.mkdir()
        (protected / "secret.txt").touch()
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)

        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-protected-writes",
                        tools=["file_write", "Write"],
                        action="deny",
                        conditions=RuleConditions(
                            path_match={"file_path": [str(protected)]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(
            tool_name="Write",
            arguments={"file_path": "../protected/secret.txt"},
        )
        assert engine.evaluate(tc).allowed is False

    def test_direct_file_path(self) -> None:
        """file_path: ~/.ssh/id_rsa matches ~/.ssh/."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-ssh",
                        tools=["*"],
                        action="deny",
                        conditions=RuleConditions(
                            path_match={"file_path": ["~/.ssh/"]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(
            tool_name="Read",
            arguments={"file_path": "~/.ssh/id_rsa"},
        )
        assert engine.evaluate(tc).allowed is False

    def test_safe_path_not_blocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """rm -rf ./build/ doesn't match specific sensitive dirs like /etc/ or ~/.ssh/."""
        monkeypatch.chdir(tmp_path)
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-sensitive-delete",
                        tools=["shell_*", "Bash"],
                        action="deny",
                        conditions=RuleConditions(
                            args_match={"command": ["rm -rf"]},
                            path_match={"command": ["/etc/", "~/.ssh/"]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(
            tool_name="Bash",
            arguments={"command": "rm -rf ./build/"},
        )
        assert engine.evaluate(tc).allowed is True

    def test_path_not_match_workspace(self, tmp_path: Path) -> None:
        """Paths inside workspace pass, paths outside fail."""
        workspace = tmp_path / "project"
        workspace.mkdir()

        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-outside-workspace",
                        tools=["Write", "Edit"],
                        action="deny",
                        conditions=RuleConditions(
                            path_not_match={"file_path": ["__workspace__"]},
                            workspace=str(workspace),
                        ),
                    ),
                ],
            )
        )
        # Inside workspace — path_not_match finds it inside → condition True
        # → inverted: rule should NOT match → allow
        tc_inside = ToolCall(
            tool_name="Write",
            arguments={"file_path": str(workspace / "main.py")},
        )
        assert engine.evaluate(tc_inside).allowed is True

        # Outside workspace — path_not_match finds it outside → condition False
        # → inverted: rule matches → deny
        tc_outside = ToolCall(
            tool_name="Write",
            arguments={"file_path": "/etc/passwd"},
        )
        assert engine.evaluate(tc_outside).allowed is False

    def test_symlink_escape(self, tmp_path: Path) -> None:
        """Symlink to /etc caught via resolve."""
        # Create a symlink that points to /etc
        link = tmp_path / "sneaky"
        link.symlink_to("/etc")
        target = str(link / "passwd")

        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-etc",
                        tools=["*"],
                        action="deny",
                        conditions=RuleConditions(
                            path_match={"file_path": ["/etc/"]},
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="Read", arguments={"file_path": target})
        assert engine.evaluate(tc).allowed is False

    def test_backward_compat(self) -> None:
        """Existing args_match-only rules are unchanged."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-drop",
                        tools=["database_query"],
                        action="deny",
                        conditions=RuleConditions(args_match={"query": ["DROP"]}),
                    ),
                ],
            )
        )
        tc = ToolCall(tool_name="database_query", arguments={"query": "DROP TABLE x"})
        assert engine.evaluate(tc).allowed is False
        tc2 = ToolCall(tool_name="database_query", arguments={"query": "SELECT 1"})
        assert engine.evaluate(tc2).allowed is True

    def test_workspace_sentinel_replaced(self, tmp_path: Path) -> None:
        """__workspace__ in patterns is replaced with workspace root."""
        workspace = tmp_path / "myproject"
        workspace.mkdir()
        target = workspace / "src" / "main.py"
        target.parent.mkdir(parents=True)
        target.touch()

        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="workspace-only",
                        tools=["Write"],
                        action="deny",
                        conditions=RuleConditions(
                            path_match={"file_path": ["__workspace__"]},
                            workspace=str(workspace),
                        ),
                    ),
                ],
            )
        )
        tc = ToolCall(
            tool_name="Write",
            arguments={"file_path": str(target)},
        )
        # File IS inside workspace → path_match matches → deny
        assert engine.evaluate(tc).allowed is False

    def test_combined_args_match_and_path_match(self, tmp_path: Path) -> None:
        """Both args_match and path_match must pass (AND logic)."""
        sensitive = tmp_path / "sensitive"
        sensitive.mkdir()

        engine = PolicyEngine(
            PolicyConfig(
                default_action="allow",
                policies=[
                    PolicyRule(
                        name="block-recursive-sensitive-delete",
                        tools=["Bash"],
                        action="deny",
                        conditions=RuleConditions(
                            args_match={"command": ["rm -rf"]},
                            path_match={"command": [str(sensitive)]},
                        ),
                    ),
                ],
            )
        )
        # Has rm -rf AND targets sensitive dir → denied
        tc_bad = ToolCall(
            tool_name="Bash",
            arguments={"command": f"rm -rf {sensitive}/data"},
        )
        assert engine.evaluate(tc_bad).allowed is False

        # Has rm -rf but does NOT target sensitive dir → allowed
        tc_safe = ToolCall(
            tool_name="Bash",
            arguments={"command": f"rm -rf {tmp_path}/other"},
        )
        assert engine.evaluate(tc_safe).allowed is True

        # Targets sensitive dir but no rm -rf → allowed (args_match fails)
        tc_read = ToolCall(
            tool_name="Bash",
            arguments={"command": f"ls {sensitive}"},
        )
        assert engine.evaluate(tc_read).allowed is True
