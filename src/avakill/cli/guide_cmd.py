"""AvaKill guide -- interactive reference and setup menu.

Navigable menu for setup, learning, and quick reference.
Replaces the old quickstart and init commands.
"""

from __future__ import annotations

import contextlib
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.text import Text

# -------------------------------------------------------------------
# Style constants
# -------------------------------------------------------------------

_DIM_GRAY = "dim #6B7280"
_DIM_MUTED = "dim #9CA3AF"
_GOLD = "bold #FBBF24"
_CYAN = "bold #00D4FF"
_GREEN = "bold #22C55E"
_NUM = "bold #E5E7EB"
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


# -------------------------------------------------------------------
# Shared helpers
# -------------------------------------------------------------------


def _section_header(con: Console, title: str) -> None:
    tw = con.width
    header = Text()
    header.append("  \u2500\u2500 ", style="dim #00D4FF")
    header.append(title, style=_CYAN)
    header.append(" ", style="dim #00D4FF")
    header.append(
        "\u2500" * max(1, tw - len(title) - 8),
        style="dim #00D4FF",
    )
    con.print(header)
    con.print()


def _cmd(name: str, desc: str, pad: int = 36) -> str:
    """Format a command + description line."""
    return f"    [bold]{name:<{pad}}[/bold][{_DIM_MUTED}]{desc}[/{_DIM_MUTED}]"


def _muted(text: str) -> str:
    """Return text wrapped in muted style tags."""
    return f"    [{_DIM_MUTED}]{text}[/{_DIM_MUTED}]"


def _menu_item(n: str, label: str, desc: str) -> str:
    """Format a numbered menu item."""
    return f"    [{_NUM}]{n}.[/{_NUM}]  {label}[{_DIM_MUTED}]{desc}[/{_DIM_MUTED}]"


def _wait_for_back(con: Console) -> None:
    """Wait for Enter to return to main menu."""
    con.print()
    con.print(_muted("\u2190 Enter to go back"))
    with contextlib.suppress(EOFError, KeyboardInterrupt):
        input()


def _numbered_choice(
    con: Console,
    prompt_text: str,
    options: list[str],
) -> int:
    """Display numbered options and return the 0-based index."""
    con.print(f"  [bold]{prompt_text}[/bold]")
    con.print()
    for i, opt in enumerate(options, 1):
        con.print(f"    [{_NUM}]{i}.[/{_NUM}] {opt}")
    con.print()
    choices = [str(i) for i in range(1, len(options) + 1)]
    choice = Prompt.ask("  \u276f", choices=choices, console=con)
    con.print()
    return int(choice) - 1


# -------------------------------------------------------------------
# Main menu
# -------------------------------------------------------------------

# (number, label_with_padding, description)
_MAIN_ITEMS = [
    ("1", "Set up AvaKill          ", "Generate policy, install hooks"),
    ("2", "Policies                ", "Writing, validating, reviewing"),
    ("3", "Hooks & Agents          ", "Install hooks for your agents"),
    ("4", "Signing & Hardening     ", "Sign, verify, harden policies"),
    ("5", "Monitoring              ", "Logs, dashboard, audit trail"),
    ("6", "Advanced                ", "Compliance, approvals, MCP, daemon"),
    ("7", "Quick Reference         ", "All commands at a glance"),
]


def _show_main_menu(con: Console) -> None:
    con.print()
    _section_header(con, "main menu")
    for n, label, desc in _MAIN_ITEMS:
        con.print(_menu_item(n, label, desc))
    con.print()
    con.print(f"    [{_DIM_GRAY}]q.  Exit[/{_DIM_GRAY}]")
    con.print()


# -------------------------------------------------------------------
# Section 1: Set up AvaKill
# -------------------------------------------------------------------


def _section_setup(con: Console) -> None:
    _section_header(con, "set up avakill")

    from avakill.hooks.installer import detect_agents

    agents = detect_agents()
    if agents:
        agent_line = Text("    Detected agents: ")
        for i, agent in enumerate(agents):
            if i > 0:
                agent_line.append(" \u00b7 ", style="dim #4B5563")
            agent_line.append(agent, style=_GREEN)
        con.print(agent_line)
    else:
        con.print(_muted("No agents detected on this machine."))
    con.print()

    policy_path = Path("avakill.yaml")
    if policy_path.exists():
        con.print(f"    [{_GREEN}]Policy already exists:[/{_GREEN}] {policy_path}")
        con.print()
        con.print(_muted("To regenerate, delete avakill.yaml first."))
        con.print()
        con.print(_muted("Next steps:"))
        con.print(_cmd("avakill validate", "Check policy syntax"))
        con.print(_cmd("avakill hook install --agent all", "Register hooks"))
        con.print(
            _cmd("avakill dashboard --db avakill_audit.db", "Live monitoring"),
        )
        _wait_for_back(con)
        return

    templates = [
        "hooks       \u2014 Blocks catastrophic ops, allows most else",
        "default     \u2014 Denies by default, allows reads, rate-limits",
        "strict      \u2014 Explicit allowlist, writes require approval",
        "permissive  \u2014 Allows everything, logs all calls",
    ]
    template_names = ["hooks", "default", "strict", "permissive"]

    choice = _numbered_choice(con, "Choose a protection template:", templates)
    template = template_names[choice]

    src = _TEMPLATES_DIR / f"{template}.yaml"
    if not src.exists():
        con.print(f"    [red]Template not found:[/red] {src}")
        _wait_for_back(con)
        return

    shutil.copy2(src, policy_path)
    con.print(f"    [{_GREEN}]Policy generated:[/{_GREEN}] avakill.yaml ({template} template)")
    con.print()

    try:
        import yaml

        from avakill.core.policy import PolicyEngine

        data = yaml.safe_load(policy_path.read_text())
        PolicyEngine.from_dict(data)
        con.print(f"    [{_GREEN}]Validation passed[/{_GREEN}]")
    except Exception as exc:
        con.print(f"    [yellow]Validation issue:[/yellow] {exc}")
    con.print()

    if agents:
        install = Prompt.ask(
            "  Install hooks now?",
            choices=["y", "n"],
            default="y",
            console=con,
        )
        if install == "y":
            from avakill.hooks.installer import install_hook

            con.print()
            for agent in agents:
                try:
                    res = install_hook(agent)
                    con.print(
                        f"    [{_GREEN}]Hook installed:[/{_GREEN}] {agent} \u2192 {res.config_path}"
                    )
                    for w in res.warnings:
                        con.print(f"    [yellow]Warning:[/yellow] {w}")
                except Exception as exc:
                    con.print(f"    [yellow]{agent}:[/yellow] {exc}")
    con.print()

    _section_header(con, "you're protected")
    con.print("    Next steps:")
    con.print(_cmd("avakill validate", "Verify policy syntax"))
    con.print(_cmd("avakill review avakill.yaml", "Review your policy"))
    con.print(
        _cmd("avakill dashboard --db avakill_audit.db", "Watch it work"),
    )
    _wait_for_back(con)


# -------------------------------------------------------------------
# Section 2: Policies
# -------------------------------------------------------------------


def _section_policies(con: Console) -> None:
    _section_header(con, "policies")

    con.print("    [bold]Writing & editing:[/bold]")
    con.print(_cmd("avakill validate", "Check your policy is valid"))
    con.print(_cmd("avakill validate /path/to/policy", "Validate a file"))
    con.print(_cmd("avakill review avakill.yaml", "Pretty-print for review"))
    con.print()

    con.print("    [bold]Creating policies:[/bold]")
    con.print(_menu_item("1", "From a template     ", "avakill guide > Setup"))
    con.print(_menu_item("2", "With an LLM         ", "avakill schema --format=prompt"))
    con.print(_menu_item("3", "By hand             ", "docs/policy-reference.md"))
    con.print()

    con.print("    [bold]Policy structure:[/bold]")
    con.print()
    example = """\
version: "1.0"
default_action: deny

policies:
  - name: block-dangerous
    tools: ["Bash"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777"]

  - name: allow-reads
    tools: ["Read", "Glob", "Grep"]
    action: allow

  - name: allow-safe-shell
    tools: ["Bash"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: [echo, ls, cat, git, python]"""

    con.print(Syntax(example, "yaml", theme="monokai", padding=(0, 4)))
    con.print()
    con.print(_muted("Rules are evaluated top-to-bottom. First match wins."))

    _wait_for_back(con)


# -------------------------------------------------------------------
# Section 3: Hooks & Agents
# -------------------------------------------------------------------


def _section_hooks(con: Console) -> None:
    _section_header(con, "hooks & agents")

    con.print("    [bold]Supported agents:[/bold]")
    names = [
        "claude-code",
        "cursor",
        "windsurf",
        "gemini-cli",
        "openai-codex",
    ]
    agents_text = Text("    ")
    for i, name in enumerate(names):
        if i > 0:
            agents_text.append("  \u00b7  ", style="dim #4B5563")
        agents_text.append(name, style=_GREEN)
    con.print(agents_text)
    con.print()

    con.print("    [bold]Commands:[/bold]")
    con.print(_cmd("avakill hook install --agent claude-code", "Register"))
    con.print(_cmd("avakill hook uninstall --agent claude-code", "Remove"))
    con.print(_cmd("avakill hook list", "Show installed"))
    con.print(_cmd("avakill hook install --agent all", "All detected"))
    con.print()

    con.print("    [bold]How it works:[/bold]")
    con.print(_muted("Hook intercepts every tool call, evaluates against"))
    con.print(_muted("policy, blocks or allows in <1ms. Full audit trail."))
    con.print()

    con.print("    [bold]Self-protection:[/bold]")
    con.print(_muted("Agents cannot uninstall avakill, modify the policy,"))
    con.print(_muted("tamper with hook configs, or kill the daemon."))

    _wait_for_back(con)


# -------------------------------------------------------------------
# Section 4: Signing & Hardening
# -------------------------------------------------------------------


def _section_signing(con: Console) -> None:
    _section_header(con, "signing & hardening")

    con.print("    [bold]Sign policies to detect tampering:[/bold]")
    con.print()
    con.print(_cmd("avakill keygen", "Generate Ed25519 keypair"))
    con.print(_cmd("avakill sign --ed25519 avakill.yaml", "Sign"))
    con.print(_cmd("avakill verify avakill.yaml", "Verify signature"))
    con.print(_cmd("avakill check-hardening avakill.yaml", "Status report"))
    con.print()

    con.print("    [bold]HMAC signing (simpler, single key):[/bold]")
    con.print()
    con.print(_cmd("avakill sign --generate-key", "Generate HMAC key"))
    con.print(_cmd("avakill sign avakill.yaml --key <hex>", "Sign"))
    con.print()

    con.print("    [bold]Harden to prevent modification:[/bold]")
    con.print()
    con.print(_cmd("sudo avakill harden avakill.yaml", "Immutable flag"))
    con.print(_muted("macOS: chflags schg / Linux: chattr +i / needs root"))
    con.print()

    con.print("    [bold]Security templates (no root needed):[/bold]")
    con.print()
    con.print(_cmd("avakill harden --selinux", "SELinux policy"))
    con.print(_cmd("avakill harden --apparmor", "AppArmor profile"))
    con.print(_cmd("avakill harden --seccomp", "seccomp-bpf JSON"))
    con.print()

    con.print(_muted("Signing detects tampering. Hardening prevents it."))

    _wait_for_back(con)


# -------------------------------------------------------------------
# Section 5: Monitoring
# -------------------------------------------------------------------


def _section_monitoring(con: Console) -> None:
    _section_header(con, "monitoring")

    con.print("    [bold]Dashboard (live TUI):[/bold]")
    con.print(_cmd("avakill dashboard --db avakill_audit.db", "Launch"))
    con.print(_cmd("avakill dashboard --db audit.db --watch", "Auto-reload"))
    con.print(_muted("Keyboard: q=quit  r=reload policy  c=clear events"))
    con.print()

    con.print("    [bold]Logs:[/bold]")
    con.print(_cmd("avakill logs --db avakill_audit.db", "Recent events"))
    con.print(_cmd("avakill logs --db audit.db --denied-only", "Only denials"))
    con.print(_cmd("avakill logs --db audit.db --tool Bash", "Filter by tool"))
    con.print(_cmd("avakill logs --db audit.db --since 5m", "Last 5 minutes"))
    con.print(_cmd("avakill logs --db audit.db --json", "JSON output"))
    con.print(_cmd("avakill logs --db avakill_audit.db tail", "Live stream"))
    con.print()

    con.print("    [bold]Fix (recovery hints):[/bold]")
    con.print(_cmd("avakill fix --db avakill_audit.db", "Why was I blocked?"))
    con.print(_cmd("avakill fix --all --db avakill_audit.db", "All denials"))
    con.print(_cmd("avakill fix --json --db avakill_audit.db", "JSON output"))

    _wait_for_back(con)


# -------------------------------------------------------------------
# Section 6: Advanced (sub-menu)
# -------------------------------------------------------------------

_ADV_ITEMS = [
    ("1", "Compliance        ", "SOC 2, NIST, EU AI Act, ISO 42001"),
    ("2", "Approvals         ", "Human-in-the-loop approval workflow"),
    ("3", "MCP Wrapping      ", "Route MCP servers through AvaKill"),
    ("4", "Daemon            ", "Persistent evaluation daemon"),
    ("5", "Schema            ", "JSON Schema & LLM prompt generation"),
]


def _section_advanced(con: Console) -> None:
    while True:
        _section_header(con, "advanced")
        for n, label, desc in _ADV_ITEMS:
            con.print(_menu_item(n, label, desc))
        con.print()
        con.print(f"    [{_DIM_GRAY}]b.  Back to main menu[/{_DIM_GRAY}]")
        con.print()

        choice = Prompt.ask(
            "  \u276f",
            choices=["1", "2", "3", "4", "5", "b"],
            console=con,
        )
        if choice == "b":
            return

        con.clear()
        _ADV_SECTIONS[choice](con)
        con.clear()


def _advanced_compliance(con: Console) -> None:
    _section_header(con, "compliance")

    con.print("    [bold]Assess policy against frameworks:[/bold]")
    con.print()
    con.print(_cmd("avakill compliance report --policy p.yaml", "All"))
    con.print(_cmd("avakill compliance report --framework soc2", "SOC 2"))
    con.print(_cmd("avakill compliance report --framework nist-ai-rmf", "NIST"))
    con.print(_cmd("avakill compliance report --framework eu-ai-act", "EU AI"))
    con.print(_cmd("avakill compliance report --framework iso-42001", "ISO"))
    con.print()
    con.print(_cmd("avakill compliance report --format json", "JSON"))
    con.print(_cmd("avakill compliance report --format markdown", "Markdown"))
    con.print()
    con.print(_cmd("avakill compliance gaps --policy avakill.yaml", "Gaps only"))

    _wait_for_back(con)


def _advanced_approvals(con: Console) -> None:
    _section_header(con, "approvals")

    con.print("    [bold]Human-in-the-loop approval workflow:[/bold]")
    con.print()
    con.print(_muted("Policy rules with action: require_approval trigger"))
    con.print(_muted("a pending request. Human grants/rejects via CLI."))
    con.print()
    con.print(_cmd("avakill approvals list", "Show pending requests"))
    con.print(_cmd("avakill approvals grant <id-prefix>", "Approve"))
    con.print(_cmd("avakill approvals reject <id-prefix>", "Reject"))
    con.print()

    con.print("    [bold]Policy example:[/bold]")
    con.print()
    example = """\
policies:
  - name: approve-writes
    tools: [Write]
    action: require_approval"""
    con.print(Syntax(example, "yaml", theme="monokai", padding=(0, 4)))

    _wait_for_back(con)


def _advanced_mcp(con: Console) -> None:
    _section_header(con, "mcp wrapping")

    con.print("    [bold]Route MCP servers through AvaKill:[/bold]")
    con.print()
    con.print(_muted("Rewrites agent MCP configs so every tool call"))
    con.print(_muted("passes through AvaKill's policy engine first."))
    con.print()
    con.print(_cmd("avakill mcp-wrap --dry-run", "Preview (no writes)"))
    con.print(_cmd("avakill mcp-wrap --policy avakill.yaml", "Wrap all"))
    con.print(_cmd("avakill mcp-wrap --agent claude-desktop", "Wrap one"))
    con.print(_cmd("avakill mcp-unwrap", "Restore originals"))
    con.print()
    con.print(_muted("Creates .bak backup before writing. Idempotent."))
    con.print()
    con.print(
        _muted("Agents: claude-desktop, cursor, windsurf, cline, continue"),
    )

    _wait_for_back(con)


def _advanced_daemon(con: Console) -> None:
    _section_header(con, "daemon")

    con.print("    [bold]Persistent evaluation daemon:[/bold]")
    con.print()
    con.print(_cmd("avakill daemon start --policy avakill.yaml", "Start"))
    con.print(_cmd("avakill daemon start --log-db audit.db", "With logging"))
    con.print(_cmd("avakill daemon start --foreground", "Foreground"))
    con.print(_cmd("avakill daemon status", "Check if running"))
    con.print(_cmd("avakill daemon stop", "Stop"))
    con.print()
    con.print(_muted("When running, hooks evaluate through it (faster,"))
    con.print(_muted("centralized). Without it, hooks use embedded Guard."))

    _wait_for_back(con)


def _advanced_schema(con: Console) -> None:
    _section_header(con, "schema & llm prompts")

    con.print("    [bold]Export JSON Schema or generate LLM prompts:[/bold]")
    con.print()
    con.print(_cmd("avakill schema", "JSON Schema"))
    con.print(_cmd("avakill schema --compact", "Minified"))
    con.print(_cmd("avakill schema --format=prompt", "LLM prompt"))
    con.print(_cmd('avakill schema --format=prompt --tools="Bash"', "With tools"))
    con.print(_cmd('avakill schema --format=prompt --use-case="X"', "With use case"))
    con.print(_cmd("avakill schema -o schema.json", "Write to file"))
    con.print()
    con.print(_muted("The LLM prompt includes evaluation rules,"))
    con.print(_muted("self-protection docs, and example policies."))

    _wait_for_back(con)


_ADV_SECTIONS: dict[str, Callable[[Console], None]] = {
    "1": _advanced_compliance,
    "2": _advanced_approvals,
    "3": _advanced_mcp,
    "4": _advanced_daemon,
    "5": _advanced_schema,
}


# -------------------------------------------------------------------
# Section 7: Quick Reference
# -------------------------------------------------------------------


def _section_quick_ref(con: Console) -> None:
    _section_header(con, "quick reference")

    con.print("    [bold]Getting Started:[/bold]")
    con.print(_cmd("avakill guide", "This menu"))
    con.print(_cmd("avakill validate", "Check policy syntax"))
    con.print(_cmd("avakill dashboard --db audit.db", "Live monitoring"))
    con.print()

    con.print("    [bold]Day-to-day:[/bold]")
    con.print(_cmd("avakill hook install --agent <name>", "Register hooks"))
    con.print(_cmd("avakill logs --db audit.db", "View audit log"))
    con.print(_cmd("avakill fix --db audit.db", "Why was I blocked?"))
    con.print(_cmd("avakill evaluate --policy avakill.yaml", "Test a call"))
    con.print()

    con.print("    [bold]Policy workflow:[/bold]")
    con.print(_cmd("avakill review avakill.yaml", "Pretty-print"))
    con.print(_cmd("avakill approve proposed.yaml", "Activate proposed"))
    con.print()

    con.print("    [bold]Security:[/bold]")
    con.print(_cmd("avakill sign --ed25519 avakill.yaml", "Sign policy"))
    con.print(_cmd("avakill verify avakill.yaml", "Verify signature"))
    con.print(_cmd("avakill keygen", "Generate Ed25519 keypair"))
    con.print(_cmd("sudo avakill harden avakill.yaml", "Immutable flag"))
    con.print(_cmd("avakill check-hardening avakill.yaml", "Status"))
    con.print()

    con.print("    [bold]Advanced:[/bold]")
    con.print(_cmd("avakill daemon start --policy p.yaml", "Start daemon"))
    con.print(_cmd("avakill compliance report --policy p.yaml", "Compliance"))
    con.print(_cmd("avakill approvals list", "Pending approvals"))
    con.print(_cmd("avakill mcp-wrap --dry-run", "MCP wrapping"))
    con.print(_cmd("avakill schema --format=prompt", "LLM prompt"))

    _wait_for_back(con)


# -------------------------------------------------------------------
# Menu loop
# -------------------------------------------------------------------


def _run_menu(con: Console) -> None:
    sections = {
        "1": _section_setup,
        "2": _section_policies,
        "3": _section_hooks,
        "4": _section_signing,
        "5": _section_monitoring,
        "6": _section_advanced,
        "7": _section_quick_ref,
    }

    while True:
        _show_main_menu(con)
        try:
            choice = Prompt.ask(
                "  \u276f",
                choices=["1", "2", "3", "4", "5", "6", "7", "q"],
                console=con,
            )
        except (EOFError, KeyboardInterrupt):
            con.print()
            break

        if choice == "q":
            break

        con.clear()
        sections[choice](con)
        con.clear()


# -------------------------------------------------------------------
# Click command
# -------------------------------------------------------------------


@click.command()
def guide() -> None:
    """Interactive guide -- setup, learning, and reference.

    \b
    Navigable menu for:
      - Setting up AvaKill (generate policy, install hooks)
      - Learning about policies, signing, monitoring
      - Quick reference for all commands
    """
    con = Console()

    if not sys.stdin.isatty():
        con.print("[dim]Guide requires an interactive terminal.[/dim]")
        raise SystemExit(1)

    con.clear()

    from avakill.cli.banner import print_banner

    print_banner()

    _run_menu(con)
