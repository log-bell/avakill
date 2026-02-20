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
@click.option("--tcp-port", default=None, type=int, help="TCP port for daemon mode.")
@click.option(
    "--policy",
    default=None,
    help="Policy file for standalone evaluation (bypasses daemon).",
)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
@click.option(
    "--simulate-burst",
    default=None,
    type=int,
    help="Simulate N rapid calls to test rate limiting (requires --policy).",
)
def evaluate(
    agent: str,
    socket: str | None,
    tcp_port: int | None,
    policy: str | None,
    output_json: bool,
    simulate_burst: int | None,
) -> None:
    """Evaluate a tool call. Reads JSON from stdin, outputs decision.

    Exit codes: 0 = allow, 2 = deny, 1 = error.

    \b
    Modes:
      Daemon mode (default): connects to running daemon via socket or TCP.
      Standalone mode (--policy): evaluates directly without daemon.

    \b
    Stdin JSON format:
      {"tool": "Bash", "args": {"command": "rm -rf /"}}
    """
    if simulate_burst is not None and not policy:
        click.echo(
            "Error: --simulate-burst requires --policy (standalone mode).",
            err=True,
        )
        raise SystemExit(1)

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

    if simulate_burst is not None:
        assert policy is not None  # guaranteed by check above
        _run_burst_simulation(policy, agent, tool, args, simulate_burst)
        return

    if policy:
        response = _evaluate_standalone(policy, agent, tool, args)
    else:
        response = _evaluate_daemon(socket, tcp_port, agent, tool, args)

    if response is None:
        raise SystemExit(1)

    if output_json:
        click.echo(response.model_dump_json())
    else:
        # Write to stderr so deny messages don't mix with piped data
        # and don't get duplicated by agent tool runners on non-zero exit.
        click.echo(f"{response.decision}: {response.reason or 'no reason'}", err=True)

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


def _run_burst_simulation(policy_path: str, agent: str, tool: str, args: dict, count: int) -> None:
    """Simulate N rapid calls and report rate limit behavior."""
    from pathlib import Path

    from rich.console import Console

    from avakill.core.engine import Guard
    from avakill.core.exceptions import RateLimitExceeded
    from avakill.core.models import ToolCall

    path = Path(policy_path)
    if not path.exists():
        click.echo(f"Error: policy file not found: {policy_path}", err=True)
        raise SystemExit(1)

    guard = Guard(policy=str(path), self_protection=False)
    console = Console(stderr=True)

    # Track runs of consecutive identical outcomes
    # Each entry: (action, reason, start_call, end_call)
    runs: list[tuple[str, str, int, int]] = []

    for i in range(1, count + 1):
        try:
            decision = guard.evaluate(tool=tool, args=args, agent_id=agent)
            action = decision.action
            if decision.policy_name:
                reason = f"rule: {decision.policy_name}"
            else:
                reason = decision.reason or ""
        except RateLimitExceeded as exc:
            action = "deny"
            reason = exc.decision.reason or "rate limit exceeded"

        if runs and runs[-1][0] == action and runs[-1][1] == reason:
            runs[-1] = (action, reason, runs[-1][2], i)
        else:
            runs.append((action, reason, i, i))

    # Format output
    parts: list[str] = []
    for action, reason, start, end in runs:
        action_upper = action.upper()
        style = "green" if action == "allow" else "red"
        if start == end:
            label = f"All {count} calls" if count == 1 else f"Call {start}"
        elif start == 1 and end == count:
            label = f"All {count} calls"
        else:
            label = f"Calls {start}-{end}"
        parts.append(f"{label}: [{style}]{action_upper}[/{style}] ({reason})")

    console.print(" | ".join(parts))

    # Hint when no rate limit is configured on the matched rule
    if len(runs) == 1 and runs[0][0] == "allow":
        try:
            probe = guard.engine.evaluate(ToolCall(tool_name=tool, arguments=args, agent_id=agent))
            for rule in guard.engine.config.policies:
                if rule.name == probe.policy_name:
                    if not rule.rate_limit:
                        console.print(
                            f"[dim]No rate limit configured on " f"matched rule '{rule.name}'[/dim]"
                        )
                    break
        except Exception:
            pass


def _evaluate_daemon(
    socket_path: str | None,
    tcp_port: int | None,
    agent: str,
    tool: str,
    args: dict,
) -> EvaluateResponse | None:
    """Evaluate via the running daemon."""
    from avakill.daemon.client import DaemonClient
    from avakill.daemon.protocol import EvaluateRequest

    client_kwargs: dict = {}
    if socket_path:
        client_kwargs["socket_path"] = socket_path
    if tcp_port is not None:
        client_kwargs["tcp_port"] = tcp_port

    client = DaemonClient(**client_kwargs)
    if not client.ping():
        click.echo(
            "Error: daemon not running. Start with 'avakill daemon start' "
            "or use --policy for standalone mode.",
            err=True,
        )
        return None

    request = EvaluateRequest(agent=agent, tool=tool, args=args)
    return client.evaluate(request)
