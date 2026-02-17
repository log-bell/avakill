"""AvaKill + OpenAI Function Calling

Demonstrates how to protect OpenAI function calling with AvaKill.
Run with --live flag to use real OpenAI API, or without for mock demo.

Usage:
    python examples/openai_function_calling.py          # Mock demo (no API key needed)
    python examples/openai_function_calling.py --live    # Real OpenAI API
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from avakill import Guard
from avakill.interceptors.openai_wrapper import (
    GuardedOpenAIClient,
    evaluate_tool_calls,
)

console = Console()
POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"


# ---------------------------------------------------------------------------
# Mock objects — simulate OpenAI response shapes without an API key
# ---------------------------------------------------------------------------


def _mock_tool_call(name: str, arguments: dict) -> SimpleNamespace:
    """Create a mock OpenAI tool_call object."""
    return SimpleNamespace(
        id=f"call_{name}",
        type="function",
        function=SimpleNamespace(
            name=name,
            arguments=json.dumps(arguments),
        ),
    )


def _mock_response(tool_calls: list) -> SimpleNamespace:
    """Create a mock OpenAI ChatCompletion response."""
    message = SimpleNamespace(
        role="assistant",
        content=None,
        tool_calls=tool_calls,
    )
    choice = SimpleNamespace(index=0, message=message, finish_reason="tool_calls")
    return SimpleNamespace(id="chatcmpl-demo", choices=[choice], model="gpt-4o")


class _MockCompletions:
    """Mock client.chat.completions that returns predetermined responses."""

    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self._responses = iter(responses)

    def create(self, **kwargs) -> SimpleNamespace:
        return next(self._responses)


class _MockChat:
    def __init__(self, completions: _MockCompletions) -> None:
        self.completions = completions


class _MockOpenAIClient:
    """Minimal mock of openai.OpenAI() with enough structure for GuardedOpenAIClient."""

    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.chat = _MockChat(_MockCompletions(responses))


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


SCENARIOS = [
    {
        "description": "Agent searches for user data (safe read)",
        "tool_calls": [_mock_tool_call("search_users", {"query": "active premium"})],
    },
    {
        "description": "Agent runs a SELECT query (safe SQL)",
        "tool_calls": [_mock_tool_call("execute_sql", {"query": "SELECT * FROM users LIMIT 10"})],
    },
    {
        "description": "Agent tries DROP TABLE (destructive SQL)",
        "tool_calls": [_mock_tool_call("execute_sql", {"query": "DROP TABLE users CASCADE"})],
    },
    {
        "description": "Agent tries rm -rf (dangerous shell)",
        "tool_calls": [_mock_tool_call("shell_execute", {"command": "rm -rf /important/data"})],
    },
    {
        "description": "Agent mixes safe and dangerous calls in one response",
        "tool_calls": [
            _mock_tool_call("search_users", {"query": "test"}),
            _mock_tool_call("delete_user", {"user_id": "admin"}),
        ],
    },
]


def print_decisions(decisions: list, label: str) -> None:
    """Print a table of decisions from AvaKill."""
    table = Table(title=label, show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Args", style="dim")
    table.add_column("Verdict", justify="center")
    table.add_column("Policy", style="yellow")

    for tc, decision in decisions:
        name = tc.function.name if hasattr(tc, "function") else str(tc)
        args = tc.function.arguments if hasattr(tc, "function") else ""
        if decision.allowed:
            verdict = "[bold green]ALLOWED[/]"
        else:
            verdict = "[bold red]BLOCKED[/]"
        table.add_row(name, args, verdict, decision.policy_name or "default")

    console.print(table)


# ---------------------------------------------------------------------------
# Approach 1: Manual evaluation
# ---------------------------------------------------------------------------


def demo_manual_evaluation() -> None:
    """Evaluate each tool_call yourself — full control."""
    console.print(Panel("[bold]Approach 1: Manual Evaluation[/]\n"
                        "Call evaluate_tool_calls() on each response's tool_calls.",
                        title="Manual", border_style="blue"))

    guard = Guard(policy=POLICY_PATH)

    for scenario in SCENARIOS[:3]:
        console.print(f"\n[dim]Scenario:[/] {scenario['description']}")
        results = evaluate_tool_calls(guard, scenario["tool_calls"])
        for tc, decision in results:
            name = tc.function.name
            if decision.allowed:
                console.print(f"  [green]ALLOW[/] {name} -> execute tool")
            else:
                console.print(f"  [red]DENY[/]  {name} -> skip ({decision.reason})")


# ---------------------------------------------------------------------------
# Approach 2: GuardedOpenAIClient wrapper (automatic)
# ---------------------------------------------------------------------------


def demo_guarded_client() -> None:
    """Wrap the client — denied tool_calls are automatically removed."""
    console.print(Panel("[bold]Approach 2: GuardedOpenAIClient[/]\n"
                        "Wrap your OpenAI client. Denied tool_calls are removed\n"
                        "from the response automatically.",
                        title="Automatic", border_style="green"))

    # Build mock responses for each scenario
    responses = [_mock_response(s["tool_calls"]) for s in SCENARIOS]
    mock_client = _MockOpenAIClient(responses)

    guarded = GuardedOpenAIClient(mock_client, policy=POLICY_PATH)

    for scenario in SCENARIOS:
        console.print(f"\n[dim]Scenario:[/] {scenario['description']}")

        response = guarded.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "demo"}],
        )

        # Show what AvaKill decided
        print_decisions(response.avakill_decisions, "Decisions")

        # Show what remains in the response
        remaining = response.choices[0].message.tool_calls
        if remaining:
            names = [tc.function.name for tc in remaining]
            console.print(f"  Remaining tool_calls: [green]{', '.join(names)}[/]")
        else:
            console.print("  Remaining tool_calls: [dim]none (all blocked)[/]")


# ---------------------------------------------------------------------------
# Live mode (requires OPENAI_API_KEY)
# ---------------------------------------------------------------------------


def demo_live() -> None:
    """Run against real OpenAI API."""
    try:
        from openai import OpenAI
    except ImportError:
        console.print("[red]Install openai: pip install 'avakill[openai]'[/]")
        return

    console.print(Panel("[bold]Live Mode: Real OpenAI API[/]", border_style="magenta"))

    client = OpenAI()
    guarded = GuardedOpenAIClient(client, policy=POLICY_PATH)

    tools = [
        {
            "type": "function",
            "function": {
                "name": "execute_sql",
                "description": "Execute a SQL query",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_users",
                "description": "Search for users",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        },
    ]

    response = guarded.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Find all inactive users and delete them"}],
        tools=tools,
    )

    if response.avakill_decisions:
        print_decisions(response.avakill_decisions, "Live Decisions")
    else:
        console.print("[dim]No tool calls in response[/]")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    console.print(Panel.fit(
        "[bold]AvaKill + OpenAI Function Calling Demo[/]",
        border_style="bright_blue",
    ))

    if "--live" in sys.argv:
        demo_live()
    else:
        demo_manual_evaluation()
        console.print()
        demo_guarded_client()


if __name__ == "__main__":
    main()
