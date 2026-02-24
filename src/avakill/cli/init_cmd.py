"""AvaKill init command - initialize a new policy file."""

from __future__ import annotations

import contextlib
import shutil
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.text import Text

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "openai": ["openai"],
    "anthropic": ["anthropic"],
    "langchain": ["langchain", "langchain-core"],
    "mcp": ["mcp"],
}

_INTEGRATION_SNIPPETS: dict[str, str] = {
    "openai": """\
from openai import OpenAI
from avakill.interceptors.openai_wrapper import GuardedOpenAIClient

client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")
response = client.chat.completions.create(...)""",
    "anthropic": """\
from anthropic import Anthropic
from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient

client = GuardedAnthropicClient(Anthropic(), policy="avakill.yaml")
response = client.messages.create(...)""",
    "langchain": """\
from avakill.interceptors.langchain_handler import AvaKillCallbackHandler

handler = AvaKillCallbackHandler(policy="avakill.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})""",
    "mcp": """\
# In your MCP client config (e.g. claude_desktop_config.json):
{
  "mcpServers": {
    "my-server": {
      "command": "avakill",
      "args": ["mcp-proxy",
               "--upstream-cmd", "python",
               "--upstream-args", "my_server.py",
               "--policy", "avakill.yaml"]
    }
  }
}""",
}


def _detect_frameworks() -> list[str]:
    """Scan the current directory for agent framework dependencies."""
    detected: list[str] = []
    cwd = Path.cwd()

    # Gather dependency text from common files
    dep_text = ""
    for filename in ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
        candidate = cwd / filename
        if candidate.exists():
            with contextlib.suppress(OSError):
                dep_text += candidate.read_text(encoding="utf-8").lower() + "\n"

    for framework, keywords in _FRAMEWORK_SIGNATURES.items():
        if any(kw in dep_text for kw in keywords):
            detected.append(framework)

    # Check for MCP server config files
    for pattern in ("**/claude_desktop_config.json", "**/mcp.json", "**/.cursor/mcp.json"):
        try:
            if list(cwd.glob(pattern)):
                if "mcp" not in detected:
                    detected.append("mcp")
                break
        except OSError:
            pass

    return detected


_PROTECTION_MODES = {
    "hooks": "Hooks only (cooperative - agents report tool calls)",
    "launch": "Launch mode (OS sandbox - contain any agent)",
    "mcp": "MCP proxy (intercept MCP tool servers)",
    "all": "All of the above (maximum protection)",
}


@click.command()
@click.option(
    "--template",
    type=click.Choice(["default", "strict", "permissive", "hooks"]),
    default=None,
    help="Policy template to use (legacy). Mutually exclusive with --rule.",
)
@click.option(
    "-o",
    "--output",
    default="avakill.yaml",
    help="Output path for the generated policy file.",
)
@click.option(
    "--mode",
    type=click.Choice(list(_PROTECTION_MODES)),
    default=None,
    help="Protection mode (hooks, launch, mcp, all).",
)
@click.option(
    "--scan/--no-scan",
    default=False,
    help="Scan project directory for sensitive files and generate targeted deny rules.",
)
@click.option(
    "--rule",
    "rules",
    multiple=True,
    help="Include a specific rule by ID. Can be repeated.",
)
@click.option(
    "--all-rules",
    is_flag=True,
    default=False,
    help="Include all optional rules.",
)
@click.option(
    "--default-action",
    type=click.Choice(["allow", "deny"]),
    default=None,
    help="Default action when no rule matches.",
)
@click.option(
    "--list-rules",
    is_flag=True,
    default=False,
    help="Print the rule catalog and exit.",
)
def init(
    template: str | None,
    output: str,
    mode: str | None,
    scan: bool,
    rules: tuple[str, ...],
    all_rules: bool,
    default_action: str | None,
    list_rules: bool,
) -> None:
    """Initialize a new AvaKill policy file.

    Use --rule to select individual rules, or --template for legacy templates.
    """
    console = Console()

    # --list-rules: print catalog and exit
    if list_rules:
        _print_rule_catalog(console)
        return

    # Mutual exclusivity: --rule/--all-rules vs --template
    has_rules = bool(rules) or all_rules
    if has_rules and template is not None:
        raise click.UsageError("--rule/--all-rules and --template are mutually exclusive.")

    output_path = Path(output)
    if output_path.exists():
        if not sys.stdin.isatty():
            console.print(
                f"[yellow]{output_path}[/yellow] already exists. "
                "Use [bold]--output[/bold] to specify a different path.",
            )
            return
        overwrite = Prompt.ask(
            f"[yellow]{output_path}[/yellow] already exists. Overwrite?",
            choices=["y", "n"],
            default="n",
            console=console,
        )
        if overwrite != "y":
            console.print("[dim]Aborted.[/dim]")
            return

    # Detect frameworks
    detected = _detect_frameworks()

    # --- Rule-based policy generation ---
    if has_rules or (template is None and not sys.stdin.isatty()):
        # Non-interactive: use --rule flags, --all-rules, or defaults
        _init_with_rules(
            console,
            output_path,
            rules=rules,
            all_rules=all_rules,
            default_action=default_action or "allow",
            scan=scan,
            detected=detected,
            mode=mode,
        )
        return

    if template is None and sys.stdin.isatty():
        # Interactive: run the toggle menu
        from avakill.cli.rule_catalog import (
            generate_yaml,
            get_optional_rules,
        )
        from avakill.cli.setup_cmd import _interactive_rule_menu

        optional = get_optional_rules()
        selected = _interactive_rule_menu(console, optional)

        if default_action is None:
            default_action = "allow"

        # Scan
        scan_rules: list[dict] = []
        if scan:
            scan_rules = _scan_for_rules(console)

        yaml_content = generate_yaml(selected, default_action, scan_rules or None)
        output_path.write_text(yaml_content, encoding="utf-8")

        console.print()
        console.print(f"[bold green]Policy file created:[/bold green] {output_path.resolve()}")
        console.print(f"[dim]Rules:[/dim] {len(selected)} optional + 3 base")
        _print_next_steps(console, output_path, detected, mode)
        return

    # --- Legacy template-based path (--template given) ---
    assert template is not None  # guaranteed by control flow above
    _init_with_template(
        console,
        output_path,
        template=template,
        scan=scan,
        detected=detected,
        mode=mode,
    )


def _print_rule_catalog(console: Console) -> None:
    """Print all available rules in a table format."""
    from avakill.cli.rule_catalog import ALL_RULES

    console.print()
    console.print("[bold]Available AvaKill rules:[/bold]")
    console.print()

    current_type = None
    for rule in ALL_RULES:
        tag = "BASE" if rule.base else ("ON" if rule.default_on else "off")
        if rule.base and current_type != "base":
            console.print("  [bold dim]Base rules (always included):[/bold dim]")
            current_type = "base"
        elif not rule.base and current_type != "optional":
            console.print()
            console.print("  [bold dim]Optional rules:[/bold dim]")
            current_type = "optional"

        style = "green" if rule.base else ("cyan" if rule.default_on else "dim")
        console.print(f"    [{style}]{rule.id:<24s}[/{style}] [{tag:>4s}]  {rule.description}")

    console.print()
    console.print("[dim]Use --rule <id> to include specific rules.[/dim]")
    console.print("[dim]Use --all-rules to include everything.[/dim]")
    console.print()


def _init_with_rules(
    console: Console,
    output_path: Path,
    *,
    rules: tuple[str, ...],
    all_rules: bool,
    default_action: str,
    scan: bool,
    detected: list[str],
    mode: str | None,
) -> None:
    """Generate policy from rule IDs (non-interactive path)."""
    from avakill.cli.rule_catalog import (
        generate_yaml,
        get_default_on_ids,
        get_optional_rule_ids,
        get_rule_by_id,
    )

    if all_rules:
        selected = get_optional_rule_ids()
    elif rules:
        # Validate rule IDs
        selected = []
        for rid in rules:
            if get_rule_by_id(rid) is None:
                raise click.ClickException(
                    f"Unknown rule ID: {rid}. Use --list-rules to see available rules."
                )
            r = get_rule_by_id(rid)
            if r is not None and not r.base:
                selected.append(rid)
    else:
        # No flags, non-TTY: use default_on rules
        selected = list(get_default_on_ids())

    scan_rules: list[dict] = []
    if scan:
        scan_rules = _scan_for_rules(console)

    yaml_content = generate_yaml(selected, default_action, scan_rules or None)
    output_path.write_text(yaml_content, encoding="utf-8")

    console.print()
    console.print(f"[bold green]Policy file created:[/bold green] {output_path.resolve()}")
    console.print(f"[dim]Rules:[/dim] {len(selected)} optional + 3 base")
    _print_next_steps(console, output_path, detected, mode)


def _init_with_template(
    console: Console,
    output_path: Path,
    *,
    template: str,
    scan: bool,
    detected: list[str],
    mode: str | None,
) -> None:
    """Legacy template-based init (backward compat)."""
    src = _TEMPLATES_DIR / f"{template}.yaml"
    if not src.exists():
        raise click.ClickException(f"Template not found: {src}")

    shutil.copy2(src, output_path)

    # Scan project for sensitive files if requested
    scan_results: list[Any] = []
    if scan:
        from avakill.cli.scanner import (
            detect_project_type,
            detect_sensitive_files,
            generate_scan_rules,
        )

        sensitive_files = detect_sensitive_files(Path.cwd())
        project_types = detect_project_type(Path.cwd())
        scan_rules = generate_scan_rules(sensitive_files, project_types)
        scan_results = sensitive_files

        if scan_rules:
            policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            existing_rules = policy_data.get("policies", [])
            policy_data["policies"] = scan_rules + existing_rules
            output_path.write_text(
                yaml.dump(policy_data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )

    # Build summary panel
    lines: list[str] = []
    lines.append(f"[bold green]Policy file created:[/bold green] {output_path.resolve()}")
    lines.append(f"[dim]Template:[/dim] {template}")
    lines.append("")

    if scan and scan_results:
        lines.append("[bold yellow]Detected sensitive files:[/bold yellow]")
        for sf in scan_results:
            lines.append(f"  [yellow]{sf.path}[/yellow] [dim]({sf.description})[/dim]")
        lines.append("")

    if detected:
        lines.append("[bold cyan]Detected frameworks:[/bold cyan]")
        for fw in detected:
            lines.append(f"  [cyan]{fw}[/cyan]")
        lines.append("")
        snippet_fw = detected[0]
        lines.append(f"[bold]Quickstart ({snippet_fw}):[/bold]")

    body = Text.from_markup("\n".join(lines))

    console.print()
    console.print(Panel(body, title="AvaKill Initialized", border_style="green", padding=(1, 2)))

    if detected:
        snippet_fw = detected[0]
        snippet = _INTEGRATION_SNIPPETS.get(snippet_fw, "")
        if snippet:
            console.print()
            lang = "json" if snippet_fw == "mcp" else "python"
            console.print(Syntax(snippet, lang, theme="monokai", padding=1))

        if len(detected) > 1:
            console.print()
            console.print("[dim]Other detected frameworks:[/dim]", ", ".join(detected[1:]))
            console.print("[dim]Run [bold]avakill init --help[/bold] for more options.[/dim]")

    _print_next_steps(console, output_path, detected, mode)


def _scan_for_rules(console: Console) -> list[dict]:
    """Scan for sensitive files and return extra rule dicts."""
    from avakill.cli.scanner import (
        detect_project_type,
        detect_sensitive_files,
        generate_scan_rules,
    )

    sensitive_files = detect_sensitive_files(Path.cwd())
    project_types = detect_project_type(Path.cwd())
    scan_rules = generate_scan_rules(sensitive_files, project_types)

    if sensitive_files:
        for sf in sensitive_files:
            console.print(f"  [yellow]{sf.path}[/yellow] [dim]({sf.description})[/dim]")

    return scan_rules


def _print_next_steps(
    console: Console,
    output_path: Path,
    detected: list[str],
    mode: str | None,
) -> None:
    """Print next steps after policy creation."""
    from avakill.hooks.installer import detect_agents

    agents = detect_agents()
    if agents:
        console.print()
        console.print(f"[bold]Detected agents:[/bold] {', '.join(agents)}")
        console.print(
            "Run [bold cyan]avakill hook install --agent all[/bold cyan] to register hooks."
        )

    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Review and customise [cyan]{output_path}[/cyan]")
    step = 2
    if detected:
        console.print(f"  {step}. Add AvaKill to your agent code (see snippet above)")
    else:
        console.print(
            f"  {step}. Add AvaKill to your agent code"
            " — see https://github.com/log-bell/avakill/blob/main/docs/getting-started.md"
        )
    step += 1

    use_hooks = mode in ("hooks", "all") or (mode is None and agents)
    use_launch = mode in ("launch", "all")
    use_mcp = mode in ("mcp", "all")

    if use_hooks:
        console.print(
            f"  {step}. Run [cyan]avakill hook install --agent all[/cyan] to register agent hooks"
        )
        step += 1
    if use_launch:
        agent_hint = agents[0] if agents else "your-agent"
        console.print(
            f"  {step}. Run [cyan]avakill launch --agent {agent_hint}[/cyan] to sandbox your agent"
        )
        step += 1
    if use_mcp:
        console.print(f"  {step}. Run [cyan]avakill mcp-wrap[/cyan] to intercept MCP tool servers")
        step += 1

    console.print(f"  {step}. Enable audit logging (see [cyan]docs/getting-started[/cyan])")
    step += 1
    console.print(f"  {step}. Run [cyan]avakill dashboard[/cyan] to monitor in real-time")
    step += 1
    console.print(f"  {step}. Run [cyan]avakill validate[/cyan] to check your policy")
    console.print()
