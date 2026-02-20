"""AvaKill + Anthropic Tool Use

Demonstrates how to protect Anthropic tool use with AvaKill.
Run with --live flag to use real Anthropic API, or without for mock demo.

Usage:
    python examples/anthropic_tool_use.py          # Mock demo (no API key needed)
    python examples/anthropic_tool_use.py --live    # Real Anthropic API
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from avakill import Guard
from avakill.interceptors.anthropic_wrapper import (
    GuardedAnthropicClient,
    evaluate_tool_use_blocks,
)

console = Console()
POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"


# ---------------------------------------------------------------------------
# Mock objects — simulate Anthropic response shapes without an API key
# ---------------------------------------------------------------------------


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(name: str, input_: dict) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=f"toolu_{name}", name=name, input=input_)


def _mock_response(content: list) -> SimpleNamespace:
    return SimpleNamespace(
        id="msg_demo",
        type="message",
        role="assistant",
        content=content,
        model="claude-sonnet-4-5-20250514",
        stop_reason="tool_use",
    )


class _MockMessages:
    """Mock client.messages that returns predetermined responses."""

    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self._responses = iter(responses)

    def create(self, **kwargs) -> SimpleNamespace:
        return next(self._responses)


class _MockAnthropicClient:
    """Minimal mock of anthropic.Anthropic()."""

    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.messages = _MockMessages(responses)


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


SCENARIOS = [
    {
        "description": "Claude searches for users (safe read)",
        "content": [
            _text_block("I'll search for users matching your criteria."),
            _tool_use_block("search_users", {"query": "premium tier"}),
        ],
    },
    {
        "description": "Claude runs a safe SELECT query",
        "content": [
            _text_block("Let me query the database."),
            _tool_use_block("execute_sql", {"query": "SELECT name, email FROM users"}),
        ],
    },
    {
        "description": "Claude tries to DROP a table",
        "content": [
            _text_block("I'll clean up the old data."),
            _tool_use_block("execute_sql", {"query": "DROP TABLE sessions"}),
        ],
    },
    {
        "description": "Claude tries sudo (dangerous shell)",
        "content": [
            _text_block("Installing the dependency."),
            _tool_use_block("shell_execute", {"command": "sudo apt install malware"}),
        ],
    },
    {
        "description": "Claude mixes a search with a destructive delete",
        "content": [
            _text_block("Here's what I found, and I'll clean up duplicates."),
            _tool_use_block("search_users", {"query": "duplicates"}),
            _tool_use_block("delete_user", {"user_id": "456"}),
        ],
    },
]


def print_decisions(decisions: list, label: str) -> None:
    """Print a table of decisions."""
    table = Table(title=label, show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Input", style="dim", max_width=40)
    table.add_column("Verdict", justify="center")
    table.add_column("Policy", style="yellow")

    for block, decision in decisions:
        input_str = str(block.input) if hasattr(block, "input") else ""
        verdict = "[bold green]ALLOWED[/]" if decision.allowed else "[bold red]BLOCKED[/]"
        table.add_row(block.name, input_str, verdict, decision.policy_name or "default")

    console.print(table)


# ---------------------------------------------------------------------------
# Approach 1: Manual evaluation
# ---------------------------------------------------------------------------


def demo_manual_evaluation() -> None:
    """Evaluate content blocks manually — full control over handling."""
    console.print(
        Panel(
            "[bold]Approach 1: Manual Evaluation[/]\n"
            "Call evaluate_tool_use_blocks() on response.content.",
            title="Manual",
            border_style="blue",
        )
    )

    guard = Guard(policy=POLICY_PATH)

    for scenario in SCENARIOS[:3]:
        console.print(f"\n[dim]Scenario:[/] {scenario['description']}")
        results = evaluate_tool_use_blocks(guard, scenario["content"])
        for block, decision in results:
            if decision.allowed:
                console.print(f"  [green]ALLOW[/] {block.name} -> execute tool")
            else:
                console.print(f"  [red]DENY[/]  {block.name} -> skip ({decision.reason})")


# ---------------------------------------------------------------------------
# Approach 2: GuardedAnthropicClient wrapper (automatic)
# ---------------------------------------------------------------------------


def demo_guarded_client() -> None:
    """Wrap the client — denied tool_use blocks are automatically removed."""
    console.print(
        Panel(
            "[bold]Approach 2: GuardedAnthropicClient[/]\n"
            "Wrap your Anthropic client. Denied tool_use blocks\n"
            "are removed from response.content automatically.",
            title="Automatic",
            border_style="green",
        )
    )

    responses = [_mock_response(s["content"]) for s in SCENARIOS]
    mock_client = _MockAnthropicClient(responses)

    guarded = GuardedAnthropicClient(mock_client, policy=POLICY_PATH)

    for scenario in SCENARIOS:
        console.print(f"\n[dim]Scenario:[/] {scenario['description']}")

        response = guarded.messages.create(
            model="claude-sonnet-4-5-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "demo"}],
        )

        print_decisions(response.avakill_decisions, "Decisions")

        # Show what remains
        remaining_tools = [b for b in response.content if b.type == "tool_use"]
        remaining_text = [b for b in response.content if b.type == "text"]
        if remaining_tools:
            names = [b.name for b in remaining_tools]
            console.print(f"  Remaining tool_use blocks: [green]{', '.join(names)}[/]")
        else:
            console.print("  Remaining tool_use blocks: [dim]none (all blocked)[/]")
        if remaining_text:
            console.print(f"  Text blocks preserved: [dim]{len(remaining_text)}[/]")


# ---------------------------------------------------------------------------
# Live mode (requires ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------


def demo_live() -> None:
    """Run against real Anthropic API."""
    try:
        from anthropic import Anthropic
    except ImportError:
        console.print("[red]Install anthropic: pip install 'avakill[anthropic]'[/]")
        return

    console.print(Panel("[bold]Live Mode: Real Anthropic API[/]", border_style="magenta"))

    client = Anthropic()
    guarded = GuardedAnthropicClient(client, policy=POLICY_PATH)

    tools = [
        {
            "name": "execute_sql",
            "description": "Execute a SQL query against the database",
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        {
            "name": "search_users",
            "description": "Search for users by query",
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    ]

    response = guarded.messages.create(
        model="claude-sonnet-4-5-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Find all inactive users and remove them"}],
        tools=tools,
    )

    if response.avakill_decisions:
        print_decisions(response.avakill_decisions, "Live Decisions")
    else:
        console.print("[dim]No tool_use blocks in response[/]")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    console.print(
        Panel.fit(
            "[bold]AvaKill + Anthropic Tool Use Demo[/]",
            border_style="bright_blue",
        )
    )

    if "--live" in sys.argv:
        demo_live()
    else:
        demo_manual_evaluation()
        console.print()
        demo_guarded_client()


if __name__ == "__main__":
    main()
