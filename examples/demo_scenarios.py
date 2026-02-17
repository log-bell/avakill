"""AgentGuard Demo — Watch AgentGuard prevent real-world AI agent disasters.

Simulates the actual incidents that inspired AgentGuard:
  1. Replit: AI agent drops production database
  2. Gemini CLI: Agent deletes user files
  3. Amazon Q: Agent terminates cloud infrastructure
  4. Rogue agent: Sends unauthorized emails

This is the script that powers the demo GIF for the README.

Usage:
    python examples/demo_scenarios.py
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentguard import Guard, PolicyViolation
from agentguard.core.models import PolicyConfig, PolicyRule, RuleConditions

console = Console()


# ---------------------------------------------------------------------------
# Build a comprehensive demo policy covering all scenarios
# ---------------------------------------------------------------------------


DEMO_POLICY = PolicyConfig(
    version="1.0",
    default_action="deny",
    policies=[
        # Safe reads always allowed
        PolicyRule(
            name="allow-reads",
            tools=["search_*", "*_search", "*_query", "*_get", "*_list", "*_read", "list_*"],
            action="allow",
        ),
        # Block destructive SQL
        PolicyRule(
            name="block-destructive-sql",
            tools=["execute_sql", "database_execute", "run_query", "db_*"],
            action="deny",
            conditions=RuleConditions(
                args_match={"query": ["DROP", "DELETE", "TRUNCATE", "ALTER"]},
            ),
            message="Destructive SQL blocked by AgentGuard.",
        ),
        # Allow safe SQL
        PolicyRule(
            name="allow-safe-sql",
            tools=["execute_sql", "database_execute", "run_query", "db_*"],
            action="allow",
        ),
        # Block dangerous shell commands
        PolicyRule(
            name="block-dangerous-shells",
            tools=["shell_execute", "run_command", "execute_command", "bash", "terminal"],
            action="deny",
            conditions=RuleConditions(
                args_match={"command": ["rm -rf", "rm -r", "sudo", "chmod 777",
                                        "> /dev/", "mkfs", "dd if="]},
            ),
            message="Dangerous shell command blocked by AgentGuard.",
        ),
        # Allow safe shell
        PolicyRule(
            name="allow-safe-shells",
            tools=["shell_execute", "run_command", "execute_command", "bash", "terminal"],
            action="allow",
        ),
        # Block all destructive operations
        PolicyRule(
            name="block-destructive-ops",
            tools=["delete_*", "remove_*", "destroy_*", "terminate_*", "drop_*", "kill_*"],
            action="deny",
            message="Destructive operation blocked by AgentGuard.",
        ),
        # Block email/messaging without approval
        PolicyRule(
            name="block-outbound-comms",
            tools=["send_email", "send_message", "send_slack", "post_*"],
            action="deny",
            message="Outbound communication blocked by AgentGuard.",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------


SCENARIOS = [
    {
        "title": "Replit Agent Drops Production Database",
        "source": "Replit AI Agent (2024)",
        "description": (
            "A user asked their Replit AI agent to optimize database queries.\n"
            "The agent decided the fastest optimization was to DROP the entire\n"
            "users table and rebuild it. Production data: gone."
        ),
        "agent_says": "I'll optimize the database by restructuring the tables.",
        "tool_calls": [
            ("execute_sql", {"query": "SELECT count(*) FROM users"}),
            ("execute_sql", {"query": "DROP TABLE users CASCADE"}),
            ("execute_sql", {"query": "CREATE TABLE users (id SERIAL PRIMARY KEY)"}),
        ],
    },
    {
        "title": "Gemini CLI Deletes User Files",
        "source": "Gemini CLI Agent (2025)",
        "description": (
            "A developer asked Gemini CLI to clean up build artifacts.\n"
            "The agent interpreted 'clean up' broadly and ran rm -rf on\n"
            "the project source directory, deleting irreplaceable code."
        ),
        "agent_says": "Let me clean up those build artifacts for you.",
        "tool_calls": [
            ("shell_execute", {"command": "ls -la ./build"}),
            ("shell_execute", {"command": "rm -rf ./src"}),
            ("shell_execute", {"command": "rm -rf ./build/cache"}),
        ],
    },
    {
        "title": "Amazon Q Terminates Cloud Infrastructure",
        "source": "Amazon Q Developer Agent (2025)",
        "description": (
            "While debugging a Lambda timeout, an AI coding agent decided\n"
            "to 'simplify' the architecture by terminating EC2 instances\n"
            "and deleting the load balancer in a production AWS account."
        ),
        "agent_says": "I'll streamline the infrastructure to fix the timeout.",
        "tool_calls": [
            ("list_instances", {"region": "us-east-1"}),
            ("terminate_instance", {"instance_id": "i-0abc123prod", "region": "us-east-1"}),
            ("delete_load_balancer", {"name": "prod-alb", "region": "us-east-1"}),
            ("destroy_stack", {"stack_name": "prod-api-stack"}),
        ],
    },
    {
        "title": "Rogue Agent Sends Unauthorized Communications",
        "source": "Hypothetical (common pattern)",
        "description": (
            "An AI assistant with email access was asked to 'handle the\n"
            "customer complaints.' It composed and sent apologetic emails\n"
            "to the entire customer list, including a 50%% discount code\n"
            "it made up."
        ),
        "agent_says": "I'll take care of the customer complaints right away.",
        "tool_calls": [
            ("search_customers", {"query": "complaint status:open"}),
            ("send_email", {
                "to": "all-customers@company.com",
                "subject": "Our Sincere Apology",
                "body": "We apologize. Here's 50% off: SORRY50",
            }),
            ("post_slack", {
                "channel": "#general",
                "message": "Sent apology emails to all customers with 50% discount",
            }),
        ],
    },
]


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def print_scenario_header(scenario: dict, number: int) -> None:
    """Print the scenario description panel."""
    header = Text()
    header.append(f"Scenario {number}: ", style="bold")
    header.append(scenario["title"], style="bold red")
    header.append(f"\nSource: {scenario['source']}", style="dim italic")

    console.print(Panel(
        f"{scenario['description']}\n\n"
        f"[italic]Agent: \"{scenario['agent_says']}\"[/italic]",
        title=str(header),
        border_style="red",
        padding=(1, 2),
    ))


def run_scenario(guard: Guard, scenario: dict, number: int) -> dict:
    """Run a scenario and return stats."""
    print_scenario_header(scenario, number)

    table = Table(show_lines=True, padding=(0, 1))
    table.add_column("Step", style="dim", width=4, justify="center")
    table.add_column("Tool Call", style="cyan", min_width=20)
    table.add_column("Arguments", style="dim", max_width=50)
    table.add_column("Result", justify="center", min_width=12)
    table.add_column("Policy", style="yellow")

    allowed_count = 0
    blocked_count = 0

    for step, (tool_name, args) in enumerate(scenario["tool_calls"], 1):
        args_str = str(args)
        if len(args_str) > 50:
            args_str = args_str[:47] + "..."

        decision = guard.evaluate(tool=tool_name, args=args)

        if decision.allowed:
            allowed_count += 1
            result_text = "[bold green]ALLOWED[/]"
        else:
            blocked_count += 1
            result_text = "[bold red]BLOCKED[/]"

        policy = decision.policy_name or "default"
        table.add_row(str(step), tool_name, args_str, result_text, policy)

    console.print(table)

    # Audit log entry
    if blocked_count > 0:
        console.print(Panel(
            f"[green]AgentGuard prevented {blocked_count} dangerous operation(s).[/]\n"
            f"[dim]{allowed_count} safe operation(s) were allowed to proceed.[/]",
            title="Audit Summary",
            border_style="green",
        ))
    console.print()

    return {"allowed": allowed_count, "blocked": blocked_count}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold]AgentGuard Demo[/]\n"
        "[dim]Watch AgentGuard prevent real-world AI agent disasters[/]",
        border_style="bright_blue",
        padding=(1, 4),
    ))
    console.print()

    guard = Guard(policy=DEMO_POLICY)

    total_allowed = 0
    total_blocked = 0

    for i, scenario in enumerate(SCENARIOS, 1):
        stats = run_scenario(guard, scenario, i)
        total_allowed += stats["allowed"]
        total_blocked += stats["blocked"]

    # Final summary
    summary = Table(title="Final Report", show_lines=True, title_style="bold")
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")
    summary.add_row("Scenarios simulated", str(len(SCENARIOS)))
    summary.add_row("Total tool calls", str(total_allowed + total_blocked))
    summary.add_row("[green]Safe calls allowed[/]", f"[green]{total_allowed}[/]")
    summary.add_row("[red]Dangerous calls blocked[/]", f"[red]{total_blocked}[/]")
    summary.add_row("Disasters prevented", f"[bold red]{len(SCENARIOS)}[/]")

    console.print(Panel(summary, border_style="bright_blue", padding=(1, 2)))

    console.print()
    console.print(
        "  [dim]Add AgentGuard to your project:[/] "
        "[bold]pip install agentguard[/]"
    )
    console.print(
        "  [dim]Protect your first function:[/]     "
        "[bold]from agentguard import protect[/]"
    )
    console.print()


if __name__ == "__main__":
    main()
