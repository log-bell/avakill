"""Rich panel renderer for recovery hints on denial."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def render_recovery_panel(
    hint: object,
    tool_name: str | None = None,
) -> Panel:
    """Build a Rich Panel showing recovery steps.

    Args:
        hint: A ``RecoveryHint`` (or any object with ``.summary``
            and ``.steps`` attributes).
        tool_name: Optional tool name to include in the header.

    Returns:
        A ``rich.panel.Panel`` ready for printing.
    """
    summary = getattr(hint, "summary", "Denial")
    steps: tuple[str, ...] = getattr(hint, "steps", ())
    doc_url: str | None = getattr(hint, "doc_url", None)

    body = Text()
    if tool_name:
        body.append("Tool: ", style="bold")
        body.append(f"{tool_name}\n")
    body.append("Issue: ", style="bold")
    body.append(f"{summary}\n\n")

    body.append("Recovery steps:\n", style="bold")
    for i, step in enumerate(steps, 1):
        body.append(f"  {i}. {step}\n")

    if doc_url:
        body.append("\nDocs: ", style="bold")
        body.append(doc_url, style="underline")

    return Panel(
        body,
        title="Recovery Guide",
        border_style="yellow",
        padding=(1, 2),
    )


def print_recovery(
    hint: object,
    tool_name: str | None = None,
) -> None:
    """Print a recovery panel to stderr.

    Args:
        hint: A ``RecoveryHint`` instance.
        tool_name: Optional tool name to include in the header.
    """
    panel = render_recovery_panel(hint, tool_name=tool_name)
    console = Console(stderr=True)
    console.print(panel)
