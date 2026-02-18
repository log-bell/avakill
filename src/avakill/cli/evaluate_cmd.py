"""CLI command for evaluating a tool call against AvaKill policy."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from avakill.daemon.protocol import EvaluateResponse


@click.command()
@click.option("--agent", default="cli", help="Agent identifier.")
@click.option("--socket", default=None, help="Unix socket path for daemon mode.")
@click.option(
    "--policy",
    default=None,
    help="Policy file for standalone evaluation (bypasses daemon).",
)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def evaluate(agent: str, socket: str | None, policy: str | None, output_json: bool) -> None:
    """Evaluate a tool call. Reads JSON from stdin, outputs decision.

    Exit codes: 0 = allow, 2 = deny, 1 = error.

    \b
    Modes:
      Daemon mode (default): connects to running daemon via socket.
      Standalone mode (--policy): evaluates directly without daemon.

    \b
    Stdin JSON format:
      {"tool": "Bash", "args": {"command": "rm -rf /"}}
    """
    raw = sys.stdin.read().strip()
    if not raw:
        click.echo("Error: no input on stdin.", err=True)
        raise SystemExit(1)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        click.echo(f"Error: invalid JSON: {exc}", err=True)
        raise SystemExit(1) from None

    tool = payload.get("tool", "")
    args = payload.get("args", {})

    if not tool:
        click.echo("Error: 'tool' field required in stdin JSON.", err=True)
        raise SystemExit(1)

    if policy:
        response = _evaluate_standalone(policy, agent, tool, args)
    else:
        response = _evaluate_daemon(socket, agent, tool, args)

    if response is None:
        raise SystemExit(1)

    if output_json:
        click.echo(response.model_dump_json())
    else:
        click.echo(f"{response.decision}: {response.reason or 'no reason'}")

    if response.decision == "deny":
        raise SystemExit(2)


def _evaluate_standalone(
    policy_path: str, agent: str, tool: str, args: dict
) -> EvaluateResponse | None:
    """Evaluate directly using Guard (no daemon)."""
    from pathlib import Path

    from avakill.daemon.protocol import EvaluateResponse as _EvaluateResponse

    path = Path(policy_path)
    if not path.exists():
        click.echo(f"Error: policy file not found: {policy_path}", err=True)
        return None

    from avakill.core.engine import Guard

    guard = Guard(policy=str(path))
    decision = guard.evaluate(tool=tool, args=args, agent_id=agent)

    return _EvaluateResponse(
        decision=decision.action,
        reason=decision.reason,
        policy=decision.policy_name,
        latency_ms=decision.latency_ms,
    )


def _evaluate_daemon(
    socket_path: str | None, agent: str, tool: str, args: dict
) -> EvaluateResponse | None:
    """Evaluate via the running daemon."""
    from avakill.daemon.client import DaemonClient
    from avakill.daemon.protocol import EvaluateRequest

    client = DaemonClient(socket_path=socket_path)
    if not client.ping():
        click.echo(
            "Error: daemon not running. Start with 'avakill daemon start' "
            "or use --policy for standalone mode.",
            err=True,
        )
        return None

    request = EvaluateRequest(agent=agent, tool=tool, args=args)
    return client.evaluate(request)
