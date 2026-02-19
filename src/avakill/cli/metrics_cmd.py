"""CLI command: ``avakill metrics`` — start a Prometheus metrics HTTP server."""

from __future__ import annotations

import threading

import click


@click.command("metrics")
@click.option("--port", default=9090, show_default=True, help="HTTP port for /metrics endpoint.")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind address.")
def metrics(port: int, host: str) -> None:
    """Start a Prometheus metrics HTTP server.

    Exposes AvaKill metrics at http://<host>:<port>/metrics for scraping
    by Prometheus or compatible collectors.

    Requires the [metrics] extra: pip install avakill[metrics]
    """
    try:
        from prometheus_client import start_http_server
    except ImportError as err:
        raise click.ClickException(
            'prometheus-client is not installed. Install it with: pip install "avakill[metrics]"'
        ) from err

    from avakill.metrics import get_registry

    registry = get_registry()
    click.echo(f"Starting Prometheus metrics server on {host}:{port}")
    click.echo(f"Metrics available at http://{host}:{port}/metrics")
    click.echo("Press Ctrl+C to stop.")

    start_http_server(port, addr=host, registry=registry)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        click.echo("\nMetrics server stopped.")
