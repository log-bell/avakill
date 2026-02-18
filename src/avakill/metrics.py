"""Prometheus metrics with custom CollectorRegistry and no-op fallback.

When ``prometheus-client`` is installed, this module maintains real counters,
gauges, and histograms.  When it is absent every call silently no-ops.

Install the optional extra::

    pip install avakill[metrics]
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Optional import — mirrors HAS_NACL pattern in core/integrity.py
# ---------------------------------------------------------------------------
try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

    HAS_PROMETHEUS = True
except ImportError:  # pragma: no cover
    HAS_PROMETHEUS = False


# ---------------------------------------------------------------------------
# No-op stubs
# ---------------------------------------------------------------------------
class _NoOpMetric:
    """Stand-in for any Prometheus metric when the library is absent."""

    def labels(self, *args: Any, **kwargs: Any) -> _NoOpMetric:  # noqa: ARG002
        return self

    def inc(self, amount: float = 1) -> None:  # noqa: ARG002
        pass

    def observe(self, value: float) -> None:  # noqa: ARG002
        pass

    def set(self, value: float) -> None:  # noqa: ARG002
        pass


class _NoOpRegistry:
    """Stand-in for ``CollectorRegistry``."""


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_registry: Any = None
_evaluations: Any = None
_violations: Any = None
_duration: Any = None
_policies_loaded: Any = None
_sp_blocks: Any = None
_reloads: Any = None
_reload_failures: Any = None
_reload_last_success: Any = None


def _ensure_metrics() -> None:
    """Create Prometheus instruments on first use."""
    global _registry, _evaluations, _violations, _duration, _policies_loaded, _sp_blocks  # noqa: PLW0603
    global _reloads, _reload_failures, _reload_last_success  # noqa: PLW0603
    if _evaluations is not None:
        return

    if HAS_PROMETHEUS:
        _registry = CollectorRegistry()
        _evaluations = Counter(
            "avakill_evaluations_total",
            "Total tool-call evaluations",
            labelnames=["tool", "action", "agent_id"],
            registry=_registry,
        )
        _violations = Counter(
            "avakill_violations_total",
            "Total policy violations",
            labelnames=["tool", "policy"],
            registry=_registry,
        )
        _duration = Histogram(
            "avakill_evaluation_duration_seconds",
            "Evaluation latency in seconds",
            labelnames=["tool"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
            registry=_registry,
        )
        _policies_loaded = Gauge(
            "avakill_policies_loaded",
            "Number of loaded policies",
            registry=_registry,
        )
        _sp_blocks = Counter(
            "avakill_self_protection_blocks_total",
            "Self-protection blocks",
            labelnames=["tool"],
            registry=_registry,
        )
        _reloads = Counter(
            "avakill_policy_reloads_total",
            "Total policy reload attempts",
            labelnames=["trigger"],
            registry=_registry,
        )
        _reload_failures = Counter(
            "avakill_policy_reload_failures_total",
            "Total policy reload failures",
            labelnames=["trigger"],
            registry=_registry,
        )
        _reload_last_success = Gauge(
            "avakill_policy_reload_last_success_timestamp",
            "Unix timestamp of last successful policy reload",
            registry=_registry,
        )
    else:
        _registry = _NoOpRegistry()
        _evaluations = _NoOpMetric()
        _violations = _NoOpMetric()
        _duration = _NoOpMetric()
        _policies_loaded = _NoOpMetric()
        _sp_blocks = _NoOpMetric()
        _reloads = _NoOpMetric()
        _reload_failures = _NoOpMetric()
        _reload_last_success = _NoOpMetric()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_registry() -> Any:
    """Return the custom ``CollectorRegistry`` (or no-op)."""
    _ensure_metrics()
    return _registry


def inc_evaluations(tool: str, action: str, agent_id: str | None = None) -> None:
    """Increment the evaluations counter."""
    _ensure_metrics()
    _evaluations.labels(tool=tool, action=action, agent_id=agent_id or "").inc()


def inc_violations(tool: str, policy: str) -> None:
    """Increment the violations counter."""
    _ensure_metrics()
    _violations.labels(tool=tool, policy=policy).inc()


def observe_duration(tool: str, duration_seconds: float) -> None:
    """Observe an evaluation duration."""
    _ensure_metrics()
    _duration.labels(tool=tool).observe(duration_seconds)


def set_policies_loaded(count: int) -> None:
    """Set the number of loaded policies."""
    _ensure_metrics()
    _policies_loaded.set(count)


def inc_self_protection_blocks(tool: str) -> None:
    """Increment the self-protection blocks counter."""
    _ensure_metrics()
    _sp_blocks.labels(tool=tool).inc()


def inc_reloads(trigger: str) -> None:
    """Increment the policy reload attempts counter."""
    _ensure_metrics()
    _reloads.labels(trigger=trigger).inc()


def inc_reload_failures(trigger: str) -> None:
    """Increment the policy reload failures counter."""
    _ensure_metrics()
    _reload_failures.labels(trigger=trigger).inc()


def set_reload_last_success(timestamp: float) -> None:
    """Set the unix timestamp of the last successful policy reload."""
    _ensure_metrics()
    _reload_last_success.set(timestamp)


def reset_metrics() -> None:
    """Reset all metrics — for test isolation only."""
    global _registry, _evaluations, _violations, _duration, _policies_loaded, _sp_blocks  # noqa: PLW0603
    global _reloads, _reload_failures, _reload_last_success  # noqa: PLW0603
    _registry = None
    _evaluations = None
    _violations = None
    _duration = None
    _policies_loaded = None
    _sp_blocks = None
    _reloads = None
    _reload_failures = None
    _reload_last_success = None
