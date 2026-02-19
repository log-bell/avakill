"""Tests for telemetry integration in Guard._record()."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from avakill import Guard


@pytest.fixture()
def guard(tmp_path):
    """Create a Guard with a simple allow-all policy."""
    policy_file = tmp_path / "avakill.yaml"
    policy_file.write_text("version: '1.0'\ndefault_action: allow\npolicies: []\n")
    return Guard(policy=str(policy_file), self_protection=False)


@pytest.fixture()
def deny_guard(tmp_path):
    """Create a Guard with a deny-all policy."""
    policy_file = tmp_path / "avakill.yaml"
    policy_file.write_text("version: '1.0'\ndefault_action: deny\npolicies: []\n")
    return Guard(policy=str(policy_file), self_protection=False)


class TestGuardOtelIntegration:
    def test_record_evaluation_called(self, guard: Guard) -> None:
        with patch("avakill.core.engine.otel_record_evaluation") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_called_once()
            kwargs = mock.call_args
            assert kwargs[1]["tool"] == "shell"
            assert kwargs[1]["action"] == "allow"

    def test_record_duration_called(self, guard: Guard) -> None:
        with patch("avakill.core.engine.otel_record_duration") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_called_once()
            assert mock.call_args[1]["tool"] == "shell"
            assert mock.call_args[1]["duration_ms"] >= 0

    def test_record_violation_called_on_deny(self, deny_guard: Guard) -> None:
        with patch("avakill.core.engine.otel_record_violation") as mock:
            deny_guard.evaluate(tool="rm", args={})
            mock.assert_called_once()
            assert mock.call_args[1]["tool"] == "rm"

    def test_no_violation_on_allow(self, guard: Guard) -> None:
        with patch("avakill.core.engine.otel_record_violation") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_not_called()


class TestGuardPrometheusIntegration:
    def test_prom_inc_evaluations_called(self, guard: Guard) -> None:
        with patch("avakill.core.engine.prom_inc_evaluations") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_called_once()
            assert mock.call_args[1]["tool"] == "shell"

    def test_prom_observe_duration_called(self, guard: Guard) -> None:
        with patch("avakill.core.engine.prom_observe_duration") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_called_once()
            assert mock.call_args[1]["duration_seconds"] >= 0

    def test_prom_inc_violations_on_deny(self, deny_guard: Guard) -> None:
        with patch("avakill.core.engine.prom_inc_violations") as mock:
            deny_guard.evaluate(tool="rm", args={})
            mock.assert_called_once()

    def test_no_prom_violation_on_allow(self, guard: Guard) -> None:
        with patch("avakill.core.engine.prom_inc_violations") as mock:
            guard.evaluate(tool="shell", args={"cmd": "ls"})
            mock.assert_not_called()


class TestTelemetryDoesNotBreakEvaluation:
    def test_otel_failure_does_not_break_evaluate(self, guard: Guard) -> None:
        with patch(
            "avakill.core.engine.otel_record_evaluation",
            side_effect=RuntimeError("OTel broke"),
        ):
            decision = guard.evaluate(tool="shell", args={"cmd": "ls"})
            assert decision.allowed is True

    def test_prom_failure_does_not_break_evaluate(self, guard: Guard) -> None:
        with patch(
            "avakill.core.engine.prom_inc_evaluations",
            side_effect=RuntimeError("Prometheus broke"),
        ):
            decision = guard.evaluate(tool="shell", args={"cmd": "ls"})
            assert decision.allowed is True

    def test_both_fail_evaluate_still_works(self, guard: Guard) -> None:
        with (
            patch(
                "avakill.core.engine.otel_record_evaluation",
                side_effect=RuntimeError("OTel broke"),
            ),
            patch(
                "avakill.core.engine.prom_inc_evaluations",
                side_effect=RuntimeError("Prom broke"),
            ),
        ):
            decision = guard.evaluate(tool="shell", args={"cmd": "ls"})
            assert decision.allowed is True
