# Observability

AvaKill ships with dual instrumentation — OpenTelemetry and native Prometheus — so you can plug it into whatever monitoring stack you already run.

Both systems are **optional**. If the dependencies aren't installed, every telemetry call silently no-ops. If a telemetry call throws at runtime, it's caught by `contextlib.suppress(Exception)` so it never breaks a policy evaluation.

## Overview

| System | Install | What you get |
|--------|---------|-------------|
| OpenTelemetry | `pip install avakill[otel]` | Distributed traces + OTel metrics |
| Prometheus | `pip install avakill[metrics]` | Native counters, histograms, gauges |
| Both | `pip install avakill[all]` | Full observability |

## OpenTelemetry Setup

AvaKill depends on `opentelemetry-api` only (the library contract). You bring the SDK and exporter in your application.

### 1. Install

```bash
pip install avakill[otel] opentelemetry-sdk opentelemetry-exporter-otlp
```

### 2. Configure

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)
```

Or use environment variables:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_SERVICE_NAME=my-app
opentelemetry-instrument python my_app.py
```

### 3. Use

AvaKill automatically emits spans and metrics once the OTel SDK is configured. No code changes needed — `Guard.evaluate()` records everything.

For manual span wrapping:

```python
from avakill._telemetry import evaluation_span

with evaluation_span(tool="shell", agent_id="bot-1", session_id="sess-42") as span:
    decision = guard.evaluate(tool="shell", args={"cmd": "ls"})
    span.set_attribute("avakill.decision", decision.action)
```

## Prometheus Setup

### 1. Install

```bash
pip install avakill[metrics]
```

### 2. Start the metrics server

```bash
avakill metrics --port 9090
```

Or programmatically:

```python
from avakill import get_metrics_registry
from prometheus_client import start_http_server

registry = get_metrics_registry()
start_http_server(9090, registry=registry)
```

### 3. Scrape

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: avakill
    static_configs:
      - targets: ["localhost:9090"]
```

## Metrics Reference

### OTel Instruments

| Name | Type | Labels | Unit |
|------|------|--------|------|
| `avakill.evaluations` | Counter | tool, action, agent_id | — |
| `avakill.violations` | Counter | tool, policy, reason | — |
| `avakill.evaluation_duration` | Histogram | tool | ms |
| `avakill.self_protection.blocks` | Counter | tool | — |

### Prometheus Instruments

| Name | Type | Labels | Unit |
|------|------|--------|------|
| `avakill_evaluations_total` | Counter | tool, action, agent_id | — |
| `avakill_violations_total` | Counter | tool, policy | — |
| `avakill_evaluation_duration_seconds` | Histogram | tool | seconds |
| `avakill_policies_loaded` | Gauge | — | — |
| `avakill_self_protection_blocks_total` | Counter | tool | — |

**Histogram buckets (seconds):** 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0

> **Note:** The metrics above are emitted by the in-process `Guard.evaluate()` path. When using the daemon with agent hooks, the daemon process emits these metrics. Hook scripts themselves are short-lived and do not emit metrics directly — monitor the daemon process for visibility into hook-driven evaluations.

## Grafana Dashboard

A pre-built dashboard is included at `observability/grafana/dashboards/avakill-overview.json`.

**Panels:**

1. **Evaluation Rate** — `rate(avakill_evaluations_total[5m])` by tool/action
2. **Violation Rate** — `rate(avakill_violations_total[5m])` by tool/policy
3. **Duration P50/P95/P99** — `histogram_quantile()` over evaluation duration
4. **Top Denied Tools** — `topk(10, sum by (tool)(avakill_violations_total))`
5. **Self-Protection Blocks** — total count stat
6. **Policies Loaded** — current gauge value
7. **Evaluations by Action** — pie chart breakdown

## Docker Quick Start

The `observability/` directory includes a one-command setup using `grafana/otel-lgtm`:

```bash
cd observability
docker compose up -d
```

This starts the full LGTM stack (Loki, Grafana, Tempo, Mimir) in a single container:

| Service | URL |
|---------|-----|
| Grafana UI | http://localhost:3000 (admin/admin) |
| OTLP gRPC | localhost:4317 |
| OTLP HTTP | localhost:4318 |
| Prometheus UI | http://localhost:9090 |

The AvaKill dashboard is automatically provisioned.

## Production Considerations

- **Custom registry:** AvaKill uses its own `CollectorRegistry`, not the global default. This avoids metric name collisions with other libraries and gives you explicit control over what gets exported.

- **Fault isolation:** All telemetry in `Guard._record()` is wrapped in `contextlib.suppress(Exception)`. A broken OTel SDK or Prometheus client will never cause a policy evaluation to fail.

- **No SDK dependency:** AvaKill depends on `opentelemetry-api` only. The API package provides no-ops when no SDK is configured, making it safe to install in any environment.

- **OTLP is the recommended export path.** The Jaeger exporter is deprecated upstream. Use OTLP to send traces to Jaeger, Tempo, Datadog, or any compatible backend.

- **Cardinality:** The `agent_id` label on evaluations can be high-cardinality if you create many unique agent IDs. Consider using a bounded set of agent identifiers in production.

- **Daemon socket latency:** When using the daemon for hook-based evaluation, add ~1-3ms for Unix socket round-trip on top of the policy evaluation time. Total hook evaluation is typically <5ms. Monitor daemon responsiveness with `avakill daemon status`.

## Further Reading

- **[Deployment Guide](deployment.md)** — production setup with Prometheus alerting and Docker patterns.
- **[CLI Reference](../cli-reference.md)** — audit log queries, compliance reports, and Prometheus metrics.
- **[Troubleshooting](troubleshooting.md#performance)** — diagnosing evaluation latency.
