"""Tests for enforcement levels (hard, soft, advisory)."""

from avakill.core.models import PolicyConfig, PolicyRule, ToolCall
from avakill.core.policy import PolicyEngine


def _make_engine(enforcement: str, action: str = "deny") -> PolicyEngine:
    """Create a PolicyEngine with a single rule at the given enforcement level."""
    config = PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(
                name="test-rule",
                tools=["dangerous_tool"],
                action=action,
                enforcement=enforcement,
                message="Test message",
            ),
        ],
    )
    return PolicyEngine(config)


def _call(tool: str = "dangerous_tool") -> ToolCall:
    return ToolCall(tool_name=tool, arguments={})


class TestEnforcementLevels:
    """Tests for enforcement level behavior."""

    def test_hard_deny_blocks(self) -> None:
        engine = _make_engine("hard", "deny")
        decision = engine.evaluate(_call())
        assert not decision.allowed
        assert decision.action == "deny"

    def test_soft_deny_blocks_by_default(self) -> None:
        engine = _make_engine("soft", "deny")
        decision = engine.evaluate(_call())
        assert not decision.allowed
        assert decision.action == "deny"

    def test_soft_deny_reason_mentions_overridable(self) -> None:
        engine = _make_engine("soft", "deny")
        decision = engine.evaluate(_call())
        assert "overridable" in decision.reason.lower()

    def test_hard_deny_reason_does_not_mention_overridable(self) -> None:
        engine = _make_engine("hard", "deny")
        decision = engine.evaluate(_call())
        assert "overridable" not in decision.reason.lower()

    def test_advisory_allows_but_logs(self) -> None:
        engine = _make_engine("advisory", "deny")
        decision = engine.evaluate(_call())
        assert decision.allowed
        assert decision.action == "allow"
        assert decision.policy_name == "test-rule"

    def test_advisory_reason_mentions_advisory(self) -> None:
        engine = _make_engine("advisory", "deny")
        decision = engine.evaluate(_call())
        assert "advisory" in decision.reason.lower()

    def test_default_enforcement_is_hard(self) -> None:
        rule = PolicyRule(name="r", tools=["t"], action="deny")
        assert rule.enforcement == "hard"

    def test_existing_yaml_without_enforcement_works(self) -> None:
        engine = PolicyEngine.from_string(
            "version: '1.0'\n"
            "default_action: deny\n"
            "policies:\n"
            "  - name: block-all\n"
            "    tools: ['*']\n"
            "    action: deny\n"
        )
        decision = engine.evaluate(_call("anything"))
        assert not decision.allowed

    def test_enforcement_field_in_json_schema(self) -> None:
        schema = PolicyRule.model_json_schema()
        assert "enforcement" in schema["properties"]
        assert set(schema["properties"]["enforcement"]["enum"]) == {
            "hard",
            "soft",
            "advisory",
        }

    def test_advisory_allow_rule_still_allows(self) -> None:
        """Advisory on an allow rule should just allow normally."""
        engine = _make_engine("advisory", "allow")
        decision = engine.evaluate(_call())
        assert decision.allowed

    def test_soft_allow_rule_still_allows(self) -> None:
        """Soft on an allow rule should just allow normally."""
        engine = _make_engine("soft", "allow")
        decision = engine.evaluate(_call())
        assert decision.allowed

    def test_unmatched_tool_uses_default_action(self) -> None:
        engine = _make_engine("hard", "deny")
        decision = engine.evaluate(_call("safe_tool"))
        assert decision.allowed  # default_action is allow
