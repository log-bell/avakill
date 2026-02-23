"""AvaKill setup — one command to go from zero to protected.

Replaces init, guide, and quickstart with a single interactive flow:
  1. Detect agents
  2. Create policy
  3. Install hooks
  4. Activity tracking
  5. Summary

Non-interactive use: avakill init --template hooks
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_ALL_AGENTS = (
    "claude-code",
    "gemini-cli",
    "cursor",
    "windsurf",
    "openai-codex",
)

_AGENT_DISPLAY: dict[str, str] = {
    "claude-code": "Claude Code",
    "gemini-cli": "Gemini CLI",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "openai-codex": "OpenAI Codex",
}

_AGENT_HINTS: dict[str, str] = {
    "claude-code": "~/.claude/",
    "gemini-cli": "~/.gemini/",
    "cursor": "~/.cursor/",
    "windsurf": "~/.codeium/windsurf/",
    "openai-codex": "~/.codex/",
}

# Template key -> display label for the summary
_TEMPLATE_LABELS: dict[str, str] = {
    "hooks": "recommended",
    "strict": "locked down",
    "permissive": "audit only",
}


def _detect_agent_locations() -> dict[str, str | None]:
    """Detect agents and return {name: location_hint | None}."""
    from avakill.hooks.installer import AGENT_DETECTORS

    results: dict[str, str | None] = {}
    for agent in _ALL_AGENTS:
        detector = AGENT_DETECTORS.get(agent)
        if detector and detector():
            results[agent] = _AGENT_HINTS.get(agent, "detected")
        else:
            results[agent] = None
    return results


def _display_config_path(agent: str) -> str:
    """Return a human-friendly config path for an agent."""
    from avakill.hooks.installer import _AGENT_CONFIG, _resolve_config_path

    cfg = _AGENT_CONFIG[agent]
    path = _resolve_config_path(cfg)
    display = str(path)
    # cwd-relative paths first (e.g. .gemini/settings.json)
    cwd = str(Path.cwd())
    if display.startswith(cwd + "/"):
        return display[len(cwd) + 1 :]
    # Home-relative paths (e.g. ~/.claude/settings.json)
    home = str(Path.home())
    if display.startswith(home):
        return "~" + display[len(home) :]
    return display


@click.command()
def setup() -> None:
    """Set up AvaKill for your AI agents.

    Interactive walkthrough that detects your agents, creates a policy,
    and installs hooks. For scripted/CI use: avakill init --template hooks
    """
    console = Console()

    if not sys.stdin.isatty():
        click.echo(
            "avakill setup requires an interactive terminal.\n"
            "\n"
            "For scripted use:\n"
            "  avakill init --template hooks          Create policy\n"
            "  avakill hook install --agent all       Install hooks",
            err=True,
        )
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Phase 1: Detection
    # ------------------------------------------------------------------
    console.print()
    console.print("  [bold]Scanning your machine...[/bold]")
    console.print()

    agent_status = _detect_agent_locations()
    detected = [a for a, loc in agent_status.items() if loc is not None]

    if not detected:
        console.print("    [bold]No AI coding agents detected.[/bold]")
        console.print()
        console.print("    AvaKill protects Claude Code, Gemini CLI, Cursor, Windsurf, and")
        console.print(
            "    OpenAI Codex. Install one of these agents, then run"
            " [bold cyan]avakill setup[/bold cyan] again."
        )
        console.print()
        console.print(
            "    If you're building with the Python SDK instead, see: [bold]avakill.com/sdk[/bold]"
        )
        console.print()
        return

    # Show detection results
    console.print("    [bold]Agents found:[/bold]")
    for agent in _ALL_AGENTS:
        display = _AGENT_DISPLAY[agent]
        location = agent_status[agent]
        line = Text()
        if location is not None:
            line.append(f"      \u2713 {display:<18s}", style="green")
            line.append(location, style="#6B7280")
        else:
            line.append(f"      \u00b7 {display:<18s}", style="#6B7280")
            line.append("not detected", style="#6B7280")
        console.print(line)

    # ------------------------------------------------------------------
    # Phase 2: Policy
    # ------------------------------------------------------------------
    console.print()

    policy_path = Path("avakill.yaml")
    template_name = "hooks"  # default

    if policy_path.exists():
        console.print(f"  [bold]Policy:[/bold] [cyan]{policy_path}[/cyan] already exists.")
        overwrite = Prompt.ask(
            "  Overwrite?",
            choices=["y", "n"],
            default="n",
            console=console,
        )
        if overwrite != "y":
            console.print("  [dim]Keeping existing policy.[/dim]")
            # Detect template from existing policy
            template_name = _detect_template(policy_path)
        else:
            template_name = _create_policy(console, policy_path)
    else:
        template_name = _create_policy(console, policy_path)

    # ------------------------------------------------------------------
    # Phase 3: Hooks
    # ------------------------------------------------------------------
    console.print()
    console.print("  [bold]Install hooks for your detected agents?[/bold]")
    console.print()
    console.print("    This adds AvaKill as a pre-tool-use check. Your agents will work")
    console.print("    normally \u2014 AvaKill only intervenes when a tool call matches a")
    console.print("    block rule.")
    console.print()

    # Show exactly which files will be modified
    for agent in detected:
        display = _AGENT_DISPLAY[agent]
        cfg_path = _display_config_path(agent)
        console.print(
            f"    \u2022 {display:<16s}\u2192 {cfg_path}",
            style="dim",
        )

    console.print()
    confirm = Prompt.ask(
        "  Install?",
        choices=["y", "n"],
        default="y",
        console=console,
    )

    hooks_installed: list[str] = []
    hooks_ok = True
    if confirm == "y":
        console.print()
        from avakill.hooks.installer import install_hook

        for agent in detected:
            display = _AGENT_DISPLAY[agent]
            try:
                result = install_hook(agent)
                if result.smoke_test_passed is False:
                    console.print(
                        f"    [yellow]\u26a0[/yellow] {display}"
                        "    [yellow]hook installed"
                        " (smoke test FAILED)[/yellow]"
                    )
                    console.print(f"      {result.command} not found on PATH.")
                    console.print("      Run: [cyan]pipx ensurepath && exec $SHELL[/cyan]")
                    hooks_installed.append(agent)
                    hooks_ok = False
                else:
                    console.print(
                        f"    [green]\u2713[/green] {display}"
                        "    hook installed"
                        " [dim](smoke test passed)[/dim]"
                    )
                    hooks_installed.append(agent)
                for w in result.warnings:
                    console.print(f"      [yellow]Warning:[/yellow] {w}")
            except Exception as exc:
                console.print(f"    [red]\u2717[/red] {display}  [red]{exc}[/red]")
                hooks_ok = False
    else:
        console.print()
        console.print("    [dim]\u00b7 Hook installation skipped.[/dim]")
        console.print("      You can install later: [cyan]avakill hook install --agent all[/cyan]")

    # ------------------------------------------------------------------
    # Phase 4: Activity tracking
    # ------------------------------------------------------------------
    console.print()
    tracking_enabled = _offer_tracking(console, policy_path)

    # ------------------------------------------------------------------
    # Phase 5: Verify + Summary
    # ------------------------------------------------------------------
    console.print()
    _verify_policy(console, policy_path)

    # Save config
    from avakill.cli.banner import mark_setup_complete
    from avakill.cli.config import mark_setup

    mark_setup_complete()
    mark_setup(protection_level=template_name)

    # Print summary
    _print_summary(
        console,
        policy_path=policy_path,
        template_name=template_name,
        tracking_enabled=tracking_enabled,
        hooks_installed=hooks_installed,
        all_ok=hooks_ok,
    )


def _offer_tracking(console: Console, policy_path: Path) -> bool:
    """Ask user about activity tracking. Returns True if enabled."""
    console.print("  [bold]Enable activity tracking?[/bold]")
    console.print()
    console.print("    This runs a lightweight background service that powers:")
    console.print(
        "      [dim]\u2022[/dim] [cyan]avakill fix[/cyan]        See why something was blocked"
    )
    console.print(
        "      [dim]\u2022[/dim] [cyan]avakill logs[/cyan]       View agent activity history"
    )
    console.print("      [dim]\u2022[/dim] [cyan]avakill dashboard[/cyan]  Live monitoring")
    console.print()
    console.print("    Without it, hooks still protect you \u2014 you just won't have")
    console.print("    history or diagnostics.")
    console.print()

    enable = Prompt.ask(
        "  Enable?",
        choices=["y", "n"],
        default="y",
        console=console,
    )

    if enable == "y":
        return _start_tracking(console, policy_path)

    console.print()
    console.print("    [dim]\u00b7 Activity tracking skipped.[/dim]")
    console.print("      You can enable it later: [cyan]avakill tracking on[/cyan]")

    from avakill.cli.config import set_tracking

    set_tracking(False)
    return False


def _start_tracking(console: Console, policy_path: Path) -> bool:
    """Start the daemon for activity tracking. Returns True on success."""
    from avakill.cli.config import get_audit_db_path, set_tracking
    from avakill.cli.tracking_cmd import _start_background

    audit_db = get_audit_db_path()
    audit_db_expanded = str(Path(audit_db).expanduser())

    pid = _start_background(str(policy_path), audit_db_expanded)

    if pid is None:
        console.print()
        console.print("    [yellow]\u2717[/yellow] Could not start activity tracking.")
        console.print("      You can try later: [cyan]avakill tracking on[/cyan]")
        set_tracking(False)
        return False

    set_tracking(True)

    db_display = audit_db.replace(str(Path.home()), "~")
    console.print()
    console.print(f"    [green]\u2713[/green] Activity tracking enabled (PID {pid})")
    console.print(f"      Logs: [dim]{db_display}[/dim]")
    return True


def _print_summary(
    console: Console,
    *,
    policy_path: Path,
    template_name: str,
    tracking_enabled: bool,
    hooks_installed: list[str],
    all_ok: bool,
) -> None:
    """Print the final setup summary."""
    sep = "\u2500" * min(53, console.width - 4)

    console.print()
    console.print(f"  [dim]{sep}[/dim]")
    console.print()

    if all_ok:
        console.print("  [bold green]Setup complete. Your agents are now protected.[/bold green]")
    else:
        console.print("  [bold yellow]Setup complete with warnings.[/bold yellow]")

    console.print()

    # Policy line
    label = _TEMPLATE_LABELS.get(template_name, template_name)
    console.print(f"    Policy:     [cyan]{policy_path}[/cyan] [dim]({label})[/dim]")

    # Tracking line
    if tracking_enabled:
        from avakill.cli.config import get_audit_db_path

        db = get_audit_db_path().replace(str(Path.home()), "~")
        console.print(f"    Tracking:   [green]enabled[/green] [dim](logging to {db})[/dim]")
    else:
        console.print("    Tracking:   [dim]off[/dim]")

    # Hooks line
    if hooks_installed:
        names = ", ".join(hooks_installed)
        console.print(f"    Hooks:      {names}")
    else:
        console.print("    Hooks:      [dim]none installed[/dim]")

    # Action items
    console.print()
    console.print("  If something gets blocked:")
    console.print("    Run  [cyan]avakill fix[/cyan]       to see why and how to fix it")
    console.print("    Edit [cyan]avakill.yaml[/cyan]   to change your rules")

    if tracking_enabled:
        console.print()
        console.print("  Monitoring:")
        console.print("    Run  [cyan]avakill logs[/cyan]      to see recent activity")
        console.print("    Run  [cyan]avakill dashboard[/cyan] for live monitoring")
    elif not tracking_enabled:
        console.print()
        console.print("  Enable activity tracking anytime: [cyan]avakill tracking on[/cyan]")

    console.print()
    console.print(f"  [dim]{sep}[/dim]")
    console.print()


def _create_policy(console: Console, policy_path: Path) -> str:
    """Interactively create a policy file. Returns template name."""
    templates = [
        ("hooks", "Recommended", "Blocks catastrophic ops, allows everything else"),
        ("strict", "Locked down", "Denies by default, explicit allowlist"),
        ("permissive", "Audit only", "Allows everything, logs all calls"),
    ]

    console.print("  [bold]Choose a protection level:[/bold]")
    console.print()
    for i, (_name, label, desc) in enumerate(templates, 1):
        line = Text()
        line.append(f"    {i}. ", style="bold")
        line.append(
            label,
            style="bold #00D4FF" if i == 1 else "bold",
        )
        line.append(f"  {desc}", style="#6B7280")
        console.print(line)

    console.print()
    choice = Prompt.ask(
        "  Choose",
        choices=["1", "2", "3"],
        default="1",
        console=console,
    )

    template_name = templates[int(choice) - 1][0]
    src = _TEMPLATES_DIR / f"{template_name}.yaml"
    if not src.exists():
        console.print(f"  [red]Template not found:[/red] {src}")
        return "hooks"

    shutil.copy2(src, policy_path)
    console.print()
    console.print(
        f"  [green]\u2713[/green] Created [cyan]{policy_path}[/cyan]"
        f" ({_TEMPLATE_LABELS.get(template_name, template_name)})"
    )
    return template_name


def _detect_template(policy_path: Path) -> str:
    """Detect which template an existing policy uses."""
    import contextlib

    import yaml

    with contextlib.suppress(Exception):
        data = yaml.safe_load(
            policy_path.read_text(encoding="utf-8"),
        )
        if isinstance(data, dict):
            action = data.get("default_action", "deny")
            if action == "allow":
                return "hooks"
    return "default"


def _verify_policy(console: Console, policy_path: Path) -> None:
    """Validate the policy file and show result."""
    if not policy_path.exists():
        console.print("  [yellow]\u2717[/yellow] No policy file to verify")
        return

    try:
        import yaml

        from avakill.core.policy import PolicyEngine

        data = yaml.safe_load(
            policy_path.read_text(encoding="utf-8"),
        )
        PolicyEngine.from_dict(data)
        rule_count = len(data.get("policies", []))
        default = data.get("default_action", "deny")
        console.print(
            f"  [green]\u2713[/green] Policy valid"
            f"  [dim]({rule_count}"
            f" rule{'s' if rule_count != 1 else ''},"
            f" default: {default})[/dim]"
        )
    except Exception as exc:
        console.print(f"  [red]\u2717[/red] Policy validation failed: {exc}")
