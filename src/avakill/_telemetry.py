"""OpenTelemetry instrumentation facade with no-op fallback.

When ``opentelemetry-api`` is installed, this module emits real traces and
metrics through the OTel API.  When it is absent every call silently no-ops,
so the rest of AvaKill never needs to care whether OTel is available.

Install the optional extra::

    pip install avakill[otel]
"""

from __future__ import annotations

import contextlib
from contextlib import contextmanager
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Optional import — mirrors the HAS_NACL pattern in core/integrity.py
# ---------------------------------------------------------------------------
try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace

    HAS_OTEL = True
except ImportError:  # pragma: no cover
    HAS_OTEL = False


# ---------------------------------------------------------------------------
# No-op stubs used when opentelemetry-api is not installed
# ---------------------------------------------------------------------------
class _NoOpSpan:
    """Minimal stand-in for ``opentelemetry.trace.Span``."""

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        pass

    def record_exception(self, exception: BaseException) -> None:  # noqa: ARG002
        pass

    def end(self) -> None:
        pass

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *_: Any) -> None:
        pass


class _NoOpTracer:
    """Minimal stand-in for ``opentelemetry.trace.Tracer``."""

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:  # noqa: ARG002
        return _NoOpSpan()

    @contextmanager
    def start_as_current_span(self, name: str, **kwargs: Any) -> Iterator[_NoOpSpan]:  # noqa: ARG002
        yield _NoOpSpan()


class _NoOpCounter:
    """Minimal stand-in for ``opentelemetry.metrics.Counter``."""

    def add(self, amount: int | float, attributes: dict[str, str] | None = None) -> None:  # noqa: ARG002
        pass


class _NoOpHistogram:
    """Minimal stand-in for ``opentelemetry.metrics.Histogram``."""

    def record(self, value: float, attributes: dict[str, str] | None = None) -> None:  # noqa: ARG002
        pass


class _NoOpMeter:
    """Minimal stand-in for ``opentelemetry.metrics.Meter``."""

    def create_counter(self, name: str, **kwargs: Any) -> _NoOpCounter:  # noqa: ARG002
        return _NoOpCounter()

    def create_histogram(self, name: str, **kwargs: Any) -> _NoOpHistogram:  # noqa: ARG002
        return _NoOpHistogram()


# ---------------------------------------------------------------------------
# Public factory helpers
# ---------------------------------------------------------------------------
def get_tracer() -> Any:
    """Return an OTel ``Tracer`` or a ``_NoOpTracer``."""
    if HAS_OTEL:
        return otel_trace.get_tracer("avakill")
    return _NoOpTracer()


def get_meter() -> Any:
    """Return an OTel ``Meter`` or a ``_NoOpMeter``."""
    if HAS_OTEL:
        return otel_metrics.get_meter("avakill")
    return _NoOpMeter()


# ---------------------------------------------------------------------------
# Lazy-initialised instruments
# ---------------------------------------------------------------------------
_tracer: Any = None
_meter: Any = None
_eval_counter: Any = None
_violation_counter: Any = None
_duration_histogram: Any = None
_sp_counter: Any = None


def _ensure_instruments() -> None:
    """Create instruments on first use."""
    global _tracer, _meter, _eval_counter, _violation_counter, _duration_histogram, _sp_counter  # noqa: PLW0603
    if _eval_counter is not None:
        return
    _tracer = get_tracer()
    _meter = get_meter()
    _eval_counter = _meter.create_counter(
        "avakill.evaluations",
        description="Number of tool-call evaluations",
    )
    _violation_counter = _meter.create_counter(
        "avakill.violations",
        description="Number of policy violations",
    )
    _duration_histogram = _meter.create_histogram(
        "avakill.evaluation_duration",
        unit="ms",
        description="Evaluation latency in milliseconds",
    )
    _sp_counter = _meter.create_counter(
        "avakill.self_protection.blocks",
        description="Self-protection blocks",
    )


# ---------------------------------------------------------------------------
# Public recording helpers (called from Guard._record)
# ---------------------------------------------------------------------------
def record_evaluation(tool: str, action: str, agent_id: str | None = None) -> None:
    """Increment the evaluation counter."""
    _ensure_instruments()
    attrs = {"tool": tool, "action": action}
    if agent_id:
        attrs["agent_id"] = agent_id
    _eval_counter.add(1, attributes=attrs)


def record_violation(tool: str, policy: str, reason: str | None = None) -> None:
    """Increment the violation counter."""
    _ensure_instruments()
    attrs = {"tool": tool, "policy": policy}
    if reason:
        attrs["reason"] = reason
    _violation_counter.add(1, attributes=attrs)


def record_duration(tool: str, duration_ms: float) -> None:
    """Observe evaluation latency."""
    _ensure_instruments()
    _duration_histogram.record(duration_ms, attributes={"tool": tool})


def record_self_protection_block(tool: str) -> None:
    """Increment the self-protection block counter."""
    _ensure_instruments()
    _sp_counter.add(1, attributes={"tool": tool})


@contextmanager
def evaluation_span(
    tool: str,
    agent_id: str | None = None,
    session_id: str | None = None,
) -> Iterator[Any]:
    """Context manager that wraps an evaluation in an OTel span."""
    _ensure_instruments()
    with _tracer.start_as_current_span("avakill.evaluate") as span:
        span.set_attribute("avakill.tool", tool)
        if agent_id:
            span.set_attribute("avakill.agent_id", agent_id)
        if session_id:
            span.set_attribute("avakill.session_id", session_id)
        try:
            yield span
        except Exception as exc:
            with contextlib.suppress(Exception):
                span.record_exception(exc)
            raise


def reset() -> None:
    """Reset lazy state — for test isolation only."""
    global _tracer, _meter, _eval_counter, _violation_counter, _duration_histogram, _sp_counter  # noqa: PLW0603
    _tracer = None
    _meter = None
    _eval_counter = None
    _violation_counter = None
    _duration_histogram = None
    _sp_counter = None
