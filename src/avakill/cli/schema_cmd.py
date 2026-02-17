"""AvaKill schema command - export JSON Schema and generate LLM prompts."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from avakill.schema import generate_prompt, get_json_schema_string


@click.command()
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "prompt"]),
    default="json",
    help="Output format: 'json' for JSON Schema, 'prompt' for LLM prompt.",
)
@click.option(
    "--compact",
    is_flag=True,
    default=False,
    help="Minified JSON output (only applies to --format=json).",
)
@click.option(
    "--tools",
    "tools_csv",
    default=None,
    help="Comma-separated list of tool names to include in the prompt.",
)
@click.option(
    "--use-case",
    default=None,
    help="Description of your use case (e.g. 'code assistant').",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    default=None,
    help="Write output to a file instead of stdout.",
)
def schema(
    output_format: str,
    compact: bool,
    tools_csv: str | None,
    use_case: str | None,
    output_path: str | None,
) -> None:
    """Export the AvaKill policy JSON Schema or generate an LLM prompt.

    \b
    Examples:
      avakill schema                          # JSON Schema to stdout
      avakill schema --format=prompt          # LLM prompt to stdout
      avakill schema --format=prompt \\
        --tools="file_read,shell_exec" \\
        --use-case="code assistant"           # Customized prompt
      avakill schema -o schema.json           # Write to file
      avakill schema --compact                # Minified JSON
    """
    console = Console(stderr=True)

    tools_list: list[str] | None = None
    if tools_csv:
        tools_list = [t.strip() for t in tools_csv.split(",") if t.strip()]

    if output_format == "prompt":
        result = generate_prompt(tools_list=tools_list, use_case=use_case)
    else:
        result = get_json_schema_string(compact=compact)

    if output_path:
        path = Path(output_path)
        path.write_text(result + "\n", encoding="utf-8")
        console.print(f"[green]Written to {path}[/green]")
    else:
        click.echo(result)
