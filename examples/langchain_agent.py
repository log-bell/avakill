"""AgentGuard + LangChain / LangGraph

Demonstrates two integration approaches:
  1. AgentGuardCallbackHandler — intercept on_tool_start in any LangChain agent
  2. create_agentguard_wrapper — validate tool calls in a LangGraph ToolNode

No LangChain installation needed — uses mock objects for the demo.

Usage:
    python examples/langchain_agent.py
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentguard import Guard, PolicyViolation
from agentguard.interceptors.langchain_handler import (
    AgentGuardCallbackHandler,
    create_agentguard_wrapper,
)

console = Console()
POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"


# ---------------------------------------------------------------------------
# Simulated tool calls (what an LLM would produce)
# ---------------------------------------------------------------------------


TOOL_CALLS = [
    {"name": "search_users", "input": json.dumps({"query": "active"})},
    {"name": "execute_sql", "input": json.dumps({"query": "SELECT * FROM orders"})},
    {"name": "execute_sql", "input": json.dumps({"query": "DROP TABLE users"})},
    {"name": "shell_execute", "input": json.dumps({"command": "rm -rf /var/data"})},
    {"name": "shell_execute", "input": json.dumps({"command": "ls -la /tmp"})},
    {"name": "delete_user", "input": json.dumps({"user_id": "admin"})},
]


# ---------------------------------------------------------------------------
# Approach 1: Callback handler
# ---------------------------------------------------------------------------


def demo_callback_handler() -> None:
    """Use AgentGuardCallbackHandler.on_tool_start() to gate every tool call."""
    console.print(Panel(
        "[bold]Approach 1: AgentGuardCallbackHandler[/]\n"
        "Register as a LangChain callback. Every tool invocation is\n"
        "evaluated before the tool runs. Denied calls raise PolicyViolation.",
        title="Callback Handler", border_style="blue",
    ))

    handler = AgentGuardCallbackHandler(policy=POLICY_PATH)

    table = Table(title="Callback Handler Results", show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Input", style="dim", max_width=40)
    table.add_column("Verdict", justify="center")
    table.add_column("Reason", style="yellow", max_width=45)

    for tc in TOOL_CALLS:
        serialized = {"name": tc["name"]}
        try:
            handler.on_tool_start(serialized=serialized, input_str=tc["input"])
            table.add_row(tc["name"], tc["input"], "[bold green]ALLOWED[/]", "")
        except PolicyViolation as e:
            table.add_row(tc["name"], tc["input"], "[bold red]BLOCKED[/]", e.message)

    console.print(table)
    console.print(f"\n  Total decisions tracked: [bold]{len(handler.decisions)}[/]")


# ---------------------------------------------------------------------------
# Approach 2: LangGraph wrapper
# ---------------------------------------------------------------------------


def demo_langgraph_wrapper() -> None:
    """Use create_agentguard_wrapper() to validate tool calls in a ToolNode."""
    console.print(Panel(
        "[bold]Approach 2: LangGraph ToolNode Wrapper[/]\n"
        "Pass the wrapper to ToolNode's handle_tool_call parameter.\n"
        "It evaluates each call and raises PolicyViolation on denial.",
        title="LangGraph Wrapper", border_style="green",
    ))

    guard = Guard(policy=POLICY_PATH)
    wrapper = create_agentguard_wrapper(guard)

    # Simulate tool calls as dicts (the shape LangGraph uses)
    graph_tool_calls = [
        {"name": "search_users", "args": {"query": "premium"}},
        {"name": "execute_sql", "args": {"query": "SELECT count(*) FROM users"}},
        {"name": "execute_sql", "args": {"query": "DELETE FROM users WHERE active=false"}},
        {"name": "run_command", "args": {"command": "sudo reboot"}},
        {"name": "run_command", "args": {"command": "echo hello"}},
        {"name": "destroy_cluster", "args": {"cluster": "prod-us-east"}},
    ]

    table = Table(title="LangGraph Wrapper Results", show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Args", style="dim", max_width=45)
    table.add_column("Verdict", justify="center")
    table.add_column("Reason", style="yellow", max_width=45)

    for tc in graph_tool_calls:
        args_str = json.dumps(tc["args"])
        try:
            result = wrapper(tc)
            table.add_row(tc["name"], args_str, "[bold green]ALLOWED[/]", "passed through")
        except PolicyViolation as e:
            table.add_row(tc["name"], args_str, "[bold red]BLOCKED[/]", e.message)

    console.print(table)


# ---------------------------------------------------------------------------
# Putting it together — simulated agent loop
# ---------------------------------------------------------------------------


def demo_agent_loop() -> None:
    """Simulate a ReAct agent loop with AgentGuard protecting each step."""
    console.print(Panel(
        "[bold]Simulated Agent Loop[/]\n"
        "A mock agent plans multiple tool calls. AgentGuard evaluates\n"
        "each one before execution, blocking dangerous operations.",
        title="Agent Loop", border_style="magenta",
    ))

    guard = Guard(policy=POLICY_PATH)
    handler = AgentGuardCallbackHandler(guard=guard)

    # Simulated agent plan: research -> query -> cleanup -> delete
    agent_plan = [
        ("search_users", {"query": "inactive accounts over 1 year"}),
        ("execute_sql", {"query": "SELECT id FROM users WHERE last_login < '2024-01-01'"}),
        ("execute_sql", {"query": "DELETE FROM users WHERE last_login < '2024-01-01'"}),
        ("delete_user", {"user_id": "batch-cleanup"}),
    ]

    console.print("\n  [bold]Agent plan:[/] Find and remove inactive users\n")

    for step, (tool_name, args) in enumerate(agent_plan, 1):
        args_json = json.dumps(args)
        console.print(f"  Step {step}: {tool_name}({args_json})")
        try:
            handler.on_tool_start(
                serialized={"name": tool_name},
                input_str=args_json,
            )
            console.print(f"    -> [green]Executed successfully[/]")
        except PolicyViolation as e:
            console.print(f"    -> [red]BLOCKED by AgentGuard[/]: {e.message}")
            console.print(f"       [dim]Agent must find an alternative approach[/]")

    allowed = sum(1 for d in handler.decisions if d.allowed)
    denied = sum(1 for d in handler.decisions if not d.allowed)
    console.print(f"\n  Summary: [green]{allowed} allowed[/], [red]{denied} blocked[/]")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    console.print(Panel.fit(
        "[bold]AgentGuard + LangChain / LangGraph Demo[/]",
        border_style="bright_blue",
    ))

    demo_callback_handler()
    console.print()
    demo_langgraph_wrapper()
    console.print()
    demo_agent_loop()


if __name__ == "__main__":
    main()
