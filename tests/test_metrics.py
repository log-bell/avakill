"""Tests for the Prometheus metrics module."""

from __future__ import annotations

import pytest

from avakill.metrics import (
    HAS_PROMETHEUS,
    _NoOpMetric,
    _NoOpRegistry,
    get_registry,
    inc_evaluations,
    inc_self_protection_blocks,
    inc_violations,
    observe_duration,
    reset_metrics,
    set_policies_loaded,
)


@pytest.fixture(autouse=True)
def _reset():
    """Ensure each test starts with clean metrics state."""
    reset_metrics()
    yield
    reset_metrics()


# ------------------------------------------------------------------
# No-op stubs
# ------------------------------------------------------------------
class TestNoOpClasses:
    def test_noop_metric_labels_returns_self(self) -> None:
        m = _NoOpMetric()
        assert m.labels(tool="t") is m

    def test_noop_metric_inc(self) -> None:
        m = _NoOpMetric()
        m.inc()
        m.inc(5)

    def test_noop_metric_observe(self) -> None:
        m = _NoOpMetric()
        m.observe(1.0)

    def test_noop_metric_set(self) -> None:
        m = _NoOpMetric()
        m.set(42)

    def test_noop_registry_is_plain_object(self) -> None:
        r = _NoOpRegistry()
        assert r is not None


# ------------------------------------------------------------------
# With prometheus-client installed
# ------------------------------------------------------------------
class TestWithPrometheusInstalled:
    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_has_prometheus_is_true(self) -> None:
        assert HAS_PROMETHEUS is True

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_get_registry_returns_collector_registry(self) -> None:
        from prometheus_client import CollectorRegistry

        reg = get_registry()
        assert isinstance(reg, CollectorRegistry)

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_inc_evaluations(self) -> None:
        inc_evaluations(tool="shell", action="allow", agent_id="bot")
        from prometheus_client import generate_latest

        output = generate_latest(get_registry()).decode()
        assert "avakill_evaluations_total" in output
        assert 'tool="shell"' in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_inc_violations(self) -> None:
        inc_violations(tool="rm", policy="deny_rm")
        from prometheus_client import generate_latest

        output = generate_latest(get_registry()).decode()
        assert "avakill_violations_total" in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_observe_duration(self) -> None:
        observe_duration(tool="shell", duration_seconds=0.05)
        from prometheus_client import generate_latest

        output = generate_latest(get_registry()).decode()
        assert "avakill_evaluation_duration_seconds" in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_set_policies_loaded(self) -> None:
        set_policies_loaded(5)
        from prometheus_client import generate_latest

        output = generate_latest(get_registry()).decode()
        assert "avakill_policies_loaded" in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_inc_self_protection_blocks(self) -> None:
        inc_self_protection_blocks(tool="modify_policy")
        from prometheus_client import generate_latest

        output = generate_latest(get_registry()).decode()
        assert "avakill_self_protection_blocks_total" in output

    @pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus-client not installed")
    def test_custom_registry_is_isolated(self) -> None:
        """Verify our registry is separate from the global default."""
        from prometheus_client import REGISTRY

        reg = get_registry()
        assert reg is not REGISTRY
