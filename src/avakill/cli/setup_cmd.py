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

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

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
    template_name = "custom"  # default for the new composable flow
    selected_rules: list[str] = []

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
            selected_rules = _create_policy(console, policy_path)
    else:
        selected_rules = _create_policy(console, policy_path)

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
    mark_setup(
        protection_level=template_name,
        selected_rules=selected_rules if selected_rules else None,
    )

    # Print summary
    _print_summary(
        console,
        policy_path=policy_path,
        template_name=template_name,
        tracking_enabled=tracking_enabled,
        hooks_installed=hooks_installed,
        all_ok=hooks_ok,
        selected_rules=selected_rules,
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
    selected_rules: list[str] | None = None,
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
    if template_name == "custom" and selected_rules is not None:
        from avakill.cli.rule_catalog import get_base_rules

        total = len(get_base_rules()) + len(selected_rules)
        label = f"{total} rules"
    else:
        _template_labels: dict[str, str] = {
            "hooks": "recommended",
            "strict": "locked down",
            "permissive": "audit only",
        }
        label = _template_labels.get(template_name, template_name)
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


def _create_policy(console: Console, policy_path: Path) -> list[str]:
    """Interactively create a policy file. Returns list of selected rule IDs."""
    from avakill.cli.rule_catalog import (
        generate_yaml,
        get_base_rules,
        get_optional_rules,
    )

    # Show base rules
    base_rules = get_base_rules()
    console.print("  [bold]Essential rules (always included):[/bold]")
    console.print()

    # Group base rules for display: catastrophic shell + catastrophic SQL
    console.print("    [green]\u2713[/green] Catastrophic shell commands")
    console.print("      [dim]Block rm -rf /, mkfs, dd if=, > /dev/, fork bombs[/dim]")
    console.print("    [green]\u2713[/green] Catastrophic SQL")
    console.print("      [dim]Block DROP DATABASE/SCHEMA via shell and database tools[/dim]")
    console.print()

    # Interactive toggle menu
    optional_rules = get_optional_rules()
    selected = _interactive_rule_menu(console, optional_rules)

    # Default action prompt
    console.print()
    console.print("  [bold]Default action (when no rule matches):[/bold]")
    console.print()
    console.print(
        "    [bold #00D4FF]1.[/bold #00D4FF] allow  "
        "[dim]Log and allow unmatched calls (recommended)[/dim]"
    )
    console.print(
        "    [bold]2.[/bold] deny   [dim]Block anything not explicitly allowed (stricter)[/dim]"
    )
    console.print()
    action_choice = Prompt.ask(
        "  Choose",
        choices=["1", "2"],
        default="1",
        console=console,
    )
    default_action = "allow" if action_choice == "1" else "deny"

    # Optional: sensitive file scan
    extra_rules = _maybe_scan(console)

    # Optional: configure rate limits
    _configure_rate_limits(console, selected)

    # Generate and write
    yaml_content = generate_yaml(selected, default_action, extra_rules or None)
    policy_path.write_text(yaml_content, encoding="utf-8")

    total = len(base_rules) + len(selected)
    if extra_rules:
        total += len(extra_rules)
    console.print()
    console.print(
        f"  [green]\u2713[/green] Created [cyan]{policy_path}[/cyan]"
        f" ({total} rules, default: {default_action})"
    )
    return list(selected)


def _interactive_rule_menu(
    console: Console,
    rules: list,
    selected: set[str] | None = None,
) -> list[str]:
    """Display an interactive toggle menu for optional rules.

    Rules are grouped by category with headers. Global numbering stays
    sequential across all categories so toggle-by-number works identically.

    Args:
        console: Rich Console instance.
        rules: List of RuleDef instances.
        selected: Pre-selected rule IDs. Defaults to default_on rules.

    Returns:
        List of selected rule IDs in catalog order.
    """
    from avakill.cli.rule_catalog import CATEGORY_DISPLAY, get_default_on_ids

    current = set(get_default_on_ids()) if selected is None else set(selected)

    # Build category-grouped display order (flat_rules for index mapping)
    grouped: dict[str, list] = {key: [] for key in CATEGORY_DISPLAY}
    for rule in rules:
        if rule.category in grouped:
            grouped[rule.category].append(rule)

    # flat_rules preserves the grouped display order for index mapping
    flat_rules: list = []
    for key in CATEGORY_DISPLAY:
        flat_rules.extend(grouped[key])

    while True:
        console.print("  [bold]What else should AvaKill block?[/bold]")
        console.print("  [dim]Type numbers to toggle, 'a' for all, Enter to confirm.[/dim]")
        console.print()

        num = 0
        for key, (name, desc) in CATEGORY_DISPLAY.items():
            cat_rules = grouped[key]
            if not cat_rules:
                continue

            sep = "\u2500" * 50
            console.print(f"  [bold]{name}[/bold]  [dim]{desc}[/dim]")
            console.print(f"  [dim]{sep}[/dim]")

            for rule in cat_rules:
                num += 1
                marker = "[green]\u2713[/green]" if rule.id in current else "[ ]"
                console.print(f"    {num:>2}. {marker} {rule.label}")
                console.print(f"        [dim]{rule.description}[/dim]")

            console.print()

        console.print()
        answer = Prompt.ask(
            "  Toggle",
            default="",
            console=console,
        )

        answer = answer.strip()
        if answer == "":
            break
        if answer.lower() == "a":
            # Toggle all: if all are selected, deselect all; otherwise select all
            all_ids = {r.id for r in rules}
            if all_ids <= current:
                current -= all_ids
            else:
                current |= all_ids
            console.print()
            continue

        # Parse space/comma-separated numbers
        for token in answer.replace(",", " ").split():
            try:
                idx = int(token) - 1
                if 0 <= idx < len(flat_rules):
                    rule_id = flat_rules[idx].id
                    if rule_id in current:
                        current.discard(rule_id)
                    else:
                        current.add(rule_id)
            except ValueError:
                pass
        console.print()

    # Return in catalog order (iterate original rules list)
    return [r.id for r in rules if r.id in current]


def _configure_rate_limits(console: Console, selected_ids: list[str]) -> None:
    """Prompt for custom rate limit values on configurable rules."""
    from avakill.cli.rule_catalog import get_rule_by_id

    for rule_id in selected_ids:
        rule = get_rule_by_id(rule_id)
        if rule is None or not rule.configurable:
            continue

        current_max = rule.rule_data.get("rate_limit", {}).get("max_calls", "?")
        current_window = rule.rule_data.get("rate_limit", {}).get("window", "?")
        console.print()
        console.print(
            f"  [bold]{rule.label}[/bold] — currently {current_max} calls/{current_window}"
        )
        custom = Prompt.ask(
            "  Customize max calls?",
            default=str(current_max),
            console=console,
        )
        try:
            new_val = int(custom)
            if new_val != current_max:
                # Update the rule_data in-place for this session's generation
                rule.rule_data["rate_limit"]["max_calls"] = new_val
        except ValueError:
            pass


def _maybe_scan(console: Console) -> list[dict]:
    """Offer to scan for sensitive files. Returns extra rule dicts."""
    console.print()
    console.print("  [bold]Scan project for sensitive files?[/bold]")
    console.print("  [dim]Detects .env, keys, credentials and adds deny rules.[/dim]")
    console.print()
    scan_choice = Prompt.ask(
        "  Scan?",
        choices=["y", "n"],
        default="y",
        console=console,
    )

    if scan_choice != "y":
        return []

    from avakill.cli.scanner import (
        detect_project_type,
        detect_sensitive_files,
        generate_scan_rules,
    )

    sensitive_files = detect_sensitive_files(Path.cwd())
    project_types = detect_project_type(Path.cwd())
    scan_rules = generate_scan_rules(sensitive_files, project_types)

    if sensitive_files:
        console.print()
        for sf in sensitive_files:
            console.print(f"    [yellow]\u26a0[/yellow] {sf.path} [dim]({sf.description})[/dim]")
        console.print(f"    [green]\u2713[/green] {len(scan_rules)} protective rule(s) added")
    else:
        console.print("    [dim]No sensitive files found.[/dim]")

    return scan_rules


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
