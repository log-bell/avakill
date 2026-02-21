"""AvaKill guide command - interactive protection and policy wizards."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _section_header(con: Console, title: str, tw: int) -> None:
    """Print a styled section header."""
    header = Text()
    header.append("  \u2500\u2500 ", style="dim #00D4FF")
    header.append(title, style="bold #00D4FF")
    header.append(" ", style="dim #00D4FF")
    header.append("\u2500" * max(1, tw - len(title) - 8), style="dim #00D4FF")
    con.print(header)
    con.print()


def _numbered_choice(con: Console, prompt_text: str, options: list[str]) -> int:
    """Display numbered options and return the 0-based index chosen."""
    con.print(f"  [bold]{prompt_text}[/bold]")
    con.print()
    for i, opt in enumerate(options, 1):
        con.print(f"    [bold #E5E7EB]{i}.[/bold #E5E7EB] {opt}")
    con.print()

    choices = [str(i) for i in range(1, len(options) + 1)]
    choice = Prompt.ask("    \u276f", choices=choices, console=con)
    con.print()
    return int(choice) - 1


# ---------------------------------------------------------------------------
# Protection mode wizard
# ---------------------------------------------------------------------------

_AGENT_TYPES = [
    "AI coding assistant (Claude Code, Cursor, Windsurf, Gemini CLI)",
    "Persistent AI agent / daemon (OpenClaw, SWE-Agent, Aider)",
    "Custom agent (LangChain, CrewAI, Python code)",
    "Not sure \u2014 help me decide",
]

_SHELL_ACCESS = [
    "Yes \u2014 it can run commands and write files",
    "No \u2014 API calls only",
    "Not sure",
]

# Rich style constants (shorter aliases for repeated styles)
_DIM_GRAY = "dim #6B7280"
_DIM_MUTED = "dim #9CA3AF"
_GOLD = "bold #FBBF24"


def _detect_and_show_agents(con: Console) -> list[str]:
    """Detect installed agents and display them."""
    from avakill.hooks.installer import detect_agents

    agents = detect_agents()
    if agents:
        agent_line = Text("  detected on this machine: ", style=_DIM_MUTED)
        for i, agent in enumerate(agents):
            if i > 0:
                agent_line.append(" \u00b7 ", style="dim #4B5563")
            agent_line.append(agent, style="bold #22C55E")
        con.print(agent_line)
        con.print()
    return agents


def _tree_branch(kind: str = "mid") -> str:
    """Return a Rich-styled tree branch prefix.

    kind: 'mid' for \u251c\u2500\u2500, 'end' for \u2514\u2500\u2500
    """
    ch = "\u251c\u2500\u2500" if kind == "mid" else "\u2514\u2500\u2500"
    return f"    [{_DIM_GRAY}]{ch}[/{_DIM_GRAY}] "


def _num(n: int) -> str:
    """Return a Rich-styled number prefix like '1. '."""
    return f"    [{_DIM_GRAY}]{n}.[/{_DIM_GRAY}] "


def _show_hooks_only(con: Console, tw: int, agent_hint: str) -> None:
    """Show hooks-only recommendation for coding assistants."""
    _section_header(con, "recommendation", tw)

    con.print("    For coding assistants, hooks are all you need:")
    con.print()
    con.print(f"    [{_GOLD}]Hooks[/{_GOLD}]  \u00b7  [{_DIM_MUTED}]security camera[/{_DIM_MUTED}]")
    con.print(_tree_branch("mid") + "Intercepts every tool call before it executes")
    con.print(_tree_branch("mid") + "Blocks rm -rf, DROP TABLE, etc. in <1ms")
    con.print(_tree_branch("mid") + "Full audit trail of everything your agent does")
    con.print(_tree_branch("end") + f"[cyan]avakill hook install --agent {agent_hint}[/cyan]")
    con.print()

    _section_header(con, "want more?", tw)

    con.print("    You can add OS-level sandboxing on top for defense in depth:")
    con.print(_tree_branch("end") + f"[cyan]avakill launch --agent {agent_hint}[/cyan]")
    con.print(f"    [{_DIM_MUTED}]    See: docs/upgrade-to-launch-mode.md[/{_DIM_MUTED}]")
    con.print()

    _section_header(con, "ready?", tw)

    con.print(_num(1) + "[bold]avakill init --template hooks[/bold]")
    con.print(_num(2) + f"[bold]avakill hook install --agent {agent_hint}[/bold]")
    con.print(_num(3) + "[bold]avakill dashboard[/bold]")
    con.print()


def _show_layered(con: Console, tw: int, agent_hint: str) -> None:
    """Show layered hooks+launch for persistent agents."""
    _section_header(con, "recommendation", tw)

    con.print("    For a persistent agent with shell access, use both layers:")
    con.print()
    con.print(
        f"    [{_GOLD}]Layer 1: Hooks[/{_GOLD}]  \u00b7  "
        f"[{_DIM_MUTED}]security camera[/{_DIM_MUTED}]"
    )
    con.print(_tree_branch("mid") + "Intercepts tool calls before they execute")
    con.print(_tree_branch("mid") + "Blocks rm -rf, DROP TABLE, etc. in <1ms")
    con.print(_tree_branch("end") + f"[cyan]avakill hook install --agent {agent_hint}[/cyan]")
    con.print()
    con.print(
        f"    [bold #EF4444]Layer 2: Launch mode[/bold #EF4444]"
        f"  \u00b7  [{_DIM_MUTED}]locked room[/{_DIM_MUTED}]"
    )
    con.print(_tree_branch("mid") + "Sandboxes the entire process at the OS level")
    con.print(_tree_branch("mid") + "Even if the agent bypasses hooks, the kernel blocks it")
    con.print(_tree_branch("end") + f"[cyan]avakill launch --agent {agent_hint}[/cyan]")
    con.print()

    _section_header(con, "why both?", tw)

    con.print("    Hooks alone are [bold]cooperative[/bold] \u2014 the agent reports its tool")
    con.print("    calls and AvaKill evaluates them. If the agent doesn't")
    con.print("    report a call, hooks can't stop it.")
    con.print()
    con.print("    Launch mode is [bold]mandatory[/bold] \u2014 Landlock (Linux) or sandbox-exec")
    con.print("    (macOS) restricts what the process can do at the kernel level.")
    con.print("    No report needed. No bypass possible.")
    con.print()
    con.print("    Together: hooks give you the audit trail and policy control.")
    con.print("    Launch mode gives you the hard boundary.")
    con.print()

    _section_header(con, "ready?", tw)

    con.print(_num(1) + "[bold]avakill init --template hooks[/bold]")
    con.print(_num(2) + f"[bold]avakill hook install --agent {agent_hint}[/bold]")
    con.print(_num(3) + f"[bold]avakill launch --agent {agent_hint}[/bold]")
    con.print(_num(4) + "[bold]avakill dashboard[/bold]")
    con.print()


def _show_decorator(con: Console, tw: int) -> None:
    """Show decorator/wrapper recommendation for custom agents."""
    _section_header(con, "recommendation", tw)

    con.print("    For custom agents, wrap your tool functions directly:")
    con.print()
    con.print(
        f"    [{_GOLD}]Option A: Decorator[/{_GOLD}]  \u00b7  [{_DIM_MUTED}]simplest[/{_DIM_MUTED}]"
    )
    con.print(_tree_branch("mid") + "Add @protect to any Python function")
    con.print(_tree_branch("end") + "[cyan]from avakill import Guard, protect[/cyan]")
    con.print()
    con.print(
        f"    [{_GOLD}]Option B: Framework wrapper[/{_GOLD}]"
        f"  \u00b7  [{_DIM_MUTED}]for OpenAI / Anthropic "
        f"/ LangChain[/{_DIM_MUTED}]"
    )
    con.print(_tree_branch("mid") + "Drop-in client wrappers, no code changes to your agent logic")
    con.print(_tree_branch("end") + "[cyan]See: docs/framework-integrations.md[/cyan]")
    con.print()
    con.print(
        f"    [{_GOLD}]Option C: MCP proxy[/{_GOLD}]  \u00b7  "
        f"[{_DIM_MUTED}]for MCP tool servers[/{_DIM_MUTED}]"
    )
    con.print(_tree_branch("mid") + "Transparent proxy between client and MCP server")
    con.print(
        _tree_branch("end") + "[cyan]avakill mcp-proxy "
        "--upstream-cmd python "
        "--upstream-args server.py[/cyan]"
    )
    con.print()

    _section_header(con, "ready?", tw)

    con.print(_num(1) + "[bold]avakill init --template default[/bold]")
    con.print(
        _num(2) + "[bold]Add AvaKill to your agent code[/bold] "
        f"[{_DIM_MUTED}](see snippet above)[/{_DIM_MUTED}]"
    )
    con.print(_num(3) + "[bold]avakill dashboard[/bold]")
    con.print()


def run_protection_guide(con: Console | None = None) -> None:
    """Run the interactive protection mode wizard.

    Usable standalone or embedded in ``avakill init``.
    """
    if con is None:
        con = Console()
    tw = con.width

    if not sys.stdin.isatty():
        con.print("[dim]Guide requires an interactive terminal.[/dim]")
        return

    con.print()
    agents = _detect_and_show_agents(con)

    agent_type = _numbered_choice(
        con,
        "What kind of agent are you protecting?",
        _AGENT_TYPES,
    )

    # "Not sure" -> show all agents detected and recommend
    if agent_type == 3:
        if agents:
            con.print(
                f"    [{_DIM_MUTED}]Based on what's "
                f"installed, you likely want hooks."
                f"[/{_DIM_MUTED}]"
            )
            con.print(f"    [{_DIM_MUTED}]Picking: AI coding assistant.[/{_DIM_MUTED}]")
            con.print()
            agent_type = 0
        else:
            con.print(
                f"    [{_DIM_MUTED}]No agents detected. Picking: custom agent.[/{_DIM_MUTED}]"
            )
            con.print()
            agent_type = 2

    # Determine agent hint for commands
    if agents:
        agent_hint = agents[0]
    elif agent_type == 1:
        agent_hint = "openclaw"
    else:
        agent_hint = "all"

    if agent_type == 2:
        # Custom agent -- decorator / wrapper / MCP
        _show_decorator(con, tw)
        return

    # Coding assistant or persistent daemon
    shell = _numbered_choice(
        con,
        "Does your agent have shell access?",
        _SHELL_ACCESS,
    )

    has_shell = shell != 1  # "No" is index 1

    if agent_type == 0:
        # Coding assistant
        _show_hooks_only(con, tw, agent_hint)
    elif agent_type == 1 and has_shell:
        # Persistent daemon with shell
        _show_layered(con, tw, agent_hint)
    elif agent_type == 1 and not has_shell:
        # Persistent daemon, API only
        _show_hooks_only(con, tw, agent_hint)


# ---------------------------------------------------------------------------
# Policy creation wizard
# ---------------------------------------------------------------------------

_POLICY_METHODS = [
    "Start from a template (quickest)",
    ("Have your AI agent write one (generates a prompt for any LLM)"),
    "Write it by hand (YAML reference)",
]

_TEMPLATES_INFO = [
    (
        "hooks",
        "Agent hooks",
        "Blocks catastrophic ops, allows most else. Best for AI coding agents.",
    ),
    (
        "default",
        "Balanced",
        "Denies by default. Blocks destructive ops, allows reads, rate-limits.",
    ),
    (
        "strict",
        "Maximum safety",
        "Explicit allowlist only. Writes and execution require approval.",
    ),
    (
        "permissive",
        "Audit mode",
        "Allows everything. Blocks only catastrophic ops. Logs all calls.",
    ),
]


def run_policy_guide(con: Console | None = None) -> None:
    """Run the interactive policy creation wizard."""
    if con is None:
        con = Console()
    tw = con.width

    if not sys.stdin.isatty():
        con.print("[dim]Guide requires an interactive terminal.[/dim]")
        return

    con.print()
    method = _numbered_choice(
        con,
        "How do you want to create your policy?",
        _POLICY_METHODS,
    )

    if method == 0:
        _guide_template(con, tw)
    elif method == 1:
        _guide_llm(con, tw)
    else:
        _guide_manual(con, tw)


def _guide_template(con: Console, tw: int) -> None:
    """Show template comparison and recommend one."""
    _section_header(con, "templates", tw)

    for name, label, desc in _TEMPLATES_INFO:
        line = Text("    ")
        line.append(f"{name:<12}", style=_GOLD)
        line.append(f"{label:<18}", style="bold #E5E7EB")
        line.append(desc, style=_DIM_MUTED)
        con.print(line)
    con.print()

    _section_header(con, "ready?", tw)

    con.print("    Pick one and run:")
    con.print()
    con.print(
        _num(1) + "[bold]avakill init --template hooks[/bold]"
        f"     [{_DIM_MUTED}]\u2190 most users start here"
        f"[/{_DIM_MUTED}]"
    )
    con.print(
        _num(2) + "[bold]avakill validate avakill.yaml[/bold]"
        f"     [{_DIM_MUTED}]check syntax[/{_DIM_MUTED}]"
    )
    con.print(
        _num(3) + "[bold]Edit avakill.yaml[/bold] to customize"
        f"    [{_DIM_MUTED}]docs/policy-reference.md"
        f"[/{_DIM_MUTED}]"
    )
    con.print()


def _guide_llm(con: Console, tw: int) -> None:
    """Generate a tailored LLM prompt for policy creation."""
    con.print(f"  [bold]What does your agent do?[/bold] [{_DIM_MUTED}](one line)[/{_DIM_MUTED}]")
    use_case = Prompt.ask("    \u276f", console=con)
    con.print()

    con.print(
        "  [bold]What tools can it call?[/bold] "
        f"[{_DIM_MUTED}](comma-separated, or leave blank)"
        f"[/{_DIM_MUTED}]"
    )
    tools_raw = Prompt.ask("    \u276f", default="", console=con)
    con.print()

    tools_list = [t.strip() for t in tools_raw.split(",") if t.strip()] or None

    from avakill.schema import generate_prompt

    prompt = generate_prompt(tools_list=tools_list, use_case=use_case or None)

    _section_header(con, "prompt for your LLM", tw)

    con.print("    Copy everything between the lines into Claude, ChatGPT,")
    con.print("    or any LLM. It will generate a complete avakill.yaml.")
    con.print()
    con.print(
        "  " + "\u2500" * min(60, tw - 4),
        style="dim #4B5563",
    )
    for line in prompt.splitlines():
        con.print(f"  {line}")
    con.print(
        "  " + "\u2500" * min(60, tw - 4),
        style="dim #4B5563",
    )
    con.print()

    # Try to copy to clipboard
    _try_clipboard(con, prompt)

    _section_header(con, "after your LLM generates the YAML", tw)

    con.print(_num(1) + "[bold]Save it as avakill.yaml[/bold]")
    con.print(
        _num(2) + "[bold]avakill validate avakill.yaml[/bold]"
        f"    [{_DIM_MUTED}]check syntax[/{_DIM_MUTED}]"
    )
    con.print(
        _num(3) + "[bold]avakill review avakill.yaml[/bold]"
        f"      [{_DIM_MUTED}]AI-powered policy review"
        f"[/{_DIM_MUTED}]"
    )
    con.print()


def _guide_manual(con: Console, tw: int) -> None:
    """Show annotated minimal example for hand-written policies."""
    _section_header(con, "minimal policy", tw)

    from rich.syntax import Syntax

    example = """\
version: "1.0"
default_action: deny          # block everything not explicitly allowed

policies:
  - name: allow-reads
    tools: ["search_*", "get_*", "list_*", "read_*"]
    action: allow

  - name: block-dangerous-shell
    tools: ["shell_*"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777"]
    message: "Dangerous shell command blocked."

  - name: allow-safe-shell
    tools: ["shell_*"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: [echo, ls, cat, git, python]"""

    con.print(Syntax(example, "yaml", theme="monokai", padding=(0, 2)))
    con.print()

    con.print(
        f"    [{_DIM_MUTED}]Rules are evaluated top-to-bottom. First match wins.[/{_DIM_MUTED}]"
    )
    con.print(
        f"    [{_DIM_MUTED}]Full reference: [bold]docs/policy-reference.md[/bold][/{_DIM_MUTED}]"
    )
    con.print()

    _section_header(con, "ready?", tw)

    con.print(_num(1) + "[bold]Create avakill.yaml[/bold] with the structure above")
    con.print(
        _num(2) + "[bold]avakill validate avakill.yaml[/bold]"
        f"    [{_DIM_MUTED}]check syntax[/{_DIM_MUTED}]"
    )
    con.print(
        _num(3) + "[bold]avakill dashboard[/bold]"
        f"                [{_DIM_MUTED}]watch it work"
        f"[/{_DIM_MUTED}]"
    )
    con.print()


def _try_clipboard(con: Console, text: str) -> None:
    """Attempt to copy text to the system clipboard."""
    import subprocess

    try:
        subprocess.run(
            ["pbcopy"],
            input=text.encode(),
            check=True,
            timeout=3,
            capture_output=True,
        )
        con.print("    [bold #22C55E]Copied to clipboard \u2713[/bold #22C55E]")
        con.print()
        return
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    try:
        subprocess.run(
            ["xclip", "-selection", "clipboard"],
            input=text.encode(),
            check=True,
            timeout=3,
            capture_output=True,
        )
        con.print("    [bold #22C55E]Copied to clipboard \u2713[/bold #22C55E]")
        con.print()
        return
    except (FileNotFoundError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@click.pass_context
def guide(ctx: click.Context) -> None:
    """Interactive guide for protecting your AI agents.

    \b
    Run with no subcommand for the protection mode wizard:
      avakill guide

    \b
    Or choose a specific guide:
      avakill guide policy    How to create and customize policies
    """
    if ctx.invoked_subcommand is None:
        run_protection_guide()


@guide.command()
def policy() -> None:
    """Interactive guide for creating AvaKill policies."""
    run_policy_guide()
