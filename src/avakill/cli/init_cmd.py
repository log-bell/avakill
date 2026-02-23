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
    help="Policy template to use.",
)
@click.option(
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
def init(template: str | None, output: str, mode: str | None, scan: bool) -> None:
    """Initialize a new AvaKill policy file."""
    console = Console()

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

    # Choose template
    if template is None:
        if not sys.stdin.isatty():
            template = "hooks"
        else:
            template = Prompt.ask(
                "Which policy template?",
                choices=["hooks", "default", "strict", "permissive"],
                default="hooks",
                console=console,
            )

    # Copy template
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
            # Read template, merge scan rules before template rules
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

        # Show snippet for first detected framework
        snippet_fw = detected[0]
        lines.append(f"[bold]Quickstart ({snippet_fw}):[/bold]")

    body = Text.from_markup("\n".join(lines))

    console.print()
    console.print(Panel(body, title="AvaKill Initialized", border_style="green", padding=(1, 2)))

    # Print code snippet outside the panel for proper syntax highlighting
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

    # Detect AI coding agents and suggest hook installation.
    from avakill.hooks.installer import detect_agents

    agents = detect_agents()
    if agents:
        console.print()
        console.print(f"[bold]Detected agents:[/bold] {', '.join(agents)}")
        console.print(
            "Run [bold cyan]avakill hook install --agent all[/bold cyan] to register hooks."
        )

    # Interactive mode selector (only when stdin is a TTY and --mode not given)
    if mode is None and sys.stdin.isatty() and template is None:
        console.print()
        console.print("[bold]How do you want to protect your agents?[/bold]")
        for i, (_key, desc) in enumerate(_PROTECTION_MODES.items(), 1):
            console.print(f"  {i}. {desc}")
        choice = Prompt.ask(
            "Select mode",
            choices=["1", "2", "3", "4"],
            default="1",
            console=console,
        )
        mode = list(_PROTECTION_MODES)[int(choice) - 1]

    # Print mode-specific next steps
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
