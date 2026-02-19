"""AvaKill init command - initialize a new policy file."""

from __future__ import annotations

import contextlib
import shutil
from pathlib import Path

import click
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


@click.command()
@click.option(
    "--template",
    type=click.Choice(["default", "strict", "permissive"]),
    default=None,
    help="Policy template to use.",
)
@click.option(
    "--output",
    default="avakill.yaml",
    help="Output path for the generated policy file.",
)
def init(template: str | None, output: str) -> None:
    """Initialize a new AvaKill policy file."""
    console = Console()

    output_path = Path(output)
    if output_path.exists():
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
        template = Prompt.ask(
            "Which policy template?",
            choices=["default", "strict", "permissive"],
            default="default",
            console=console,
        )

    # Copy template
    src = _TEMPLATES_DIR / f"{template}.yaml"
    if not src.exists():
        raise click.ClickException(f"Template not found: {src}")

    shutil.copy2(src, output_path)

    # Build summary panel
    lines: list[str] = []
    lines.append(f"[bold green]Policy file created:[/bold green] {output_path.resolve()}")
    lines.append(f"[dim]Template:[/dim] {template}")
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

    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Review and customise [cyan]{output_path}[/cyan]")
    step = 2
    if detected:
        console.print(f"  {step}. Add AvaKill to your agent code (see snippet above)")
    else:
        console.print(f"  {step}. Add AvaKill to your agent code — see https://avakill.com/docs/getting-started")
    step += 1
    if agents:
        console.print(
            f"  {step}. Run [cyan]avakill hook install --agent all[/cyan] to register agent hooks"
        )
        step += 1
    console.print(f"  {step}. Enable audit logging (see [cyan]docs/getting-started[/cyan])")
    step += 1
    console.print(f"  {step}. Run [cyan]avakill dashboard[/cyan] to monitor in real-time")
    step += 1
    console.print(f"  {step}. Run [cyan]avakill validate[/cyan] to check your policy")
    console.print()
