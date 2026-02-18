"""AvaKill CLI entry point."""

from __future__ import annotations

import importlib
from typing import Any

import click

# Map command name -> (module_path, attribute_name)
_COMMANDS: dict[str, tuple[str, str]] = {
    "approve": ("avakill.cli.approve_cmd", "approve"),
    "approvals": ("avakill.cli.approval_cmd", "approvals"),
    "check-hardening": ("avakill.cli.check_hardening_cmd", "check_hardening"),
    "compliance": ("avakill.cli.compliance_cmd", "compliance"),
    "daemon": ("avakill.cli.daemon_cmd", "daemon"),
    "dashboard": ("avakill.cli.dashboard_cmd", "dashboard"),
    "enforce": ("avakill.cli.enforce_cmd", "enforce"),
    "evaluate": ("avakill.cli.evaluate_cmd", "evaluate"),
    "fix": ("avakill.cli.fix_cmd", "fix"),
    "harden": ("avakill.cli.harden_cmd", "harden"),
    "hook": ("avakill.cli.hook_cmd", "hook"),
    "init": ("avakill.cli.init_cmd", "init"),
    "keygen": ("avakill.cli.keygen_cmd", "keygen"),
    "logs": ("avakill.cli.logs_cmd", "logs"),
    "mcp-proxy": ("avakill.cli.mcp_proxy_cmd", "mcp_proxy"),
    "metrics": ("avakill.cli.metrics_cmd", "metrics"),
    "review": ("avakill.cli.review_cmd", "review"),
    "schema": ("avakill.cli.schema_cmd", "schema"),
    "sign": ("avakill.cli.sign_cmd", "sign"),
    "validate": ("avakill.cli.validate_cmd", "validate"),
    "verify": ("avakill.cli.verify_cmd", "verify"),
}

_COMMAND_GROUPS: list[tuple[str, list[str]]] = [
    ("Getting Started", ["init", "validate", "dashboard", "logs"]),
    ("Integrations", ["mcp-proxy", "daemon", "hook", "evaluate"]),
    ("Security", ["sign", "verify", "keygen", "harden", "check-hardening", "review", "approve"]),
    ("Advanced", ["enforce", "compliance", "approvals", "schema", "metrics", "fix"]),
]


class LazyGroup(click.Group):
    """A Click group that imports subcommands on demand.

    ``list_commands()`` returns all known names without importing.
    ``get_command()`` imports the target module only when the command
    is actually invoked.
    """

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(_COMMANDS)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.BaseCommand | None:
        if cmd_name not in _COMMANDS:
            return None
        module_path, attr_name = _COMMANDS[cmd_name]
        mod = importlib.import_module(module_path)
        return getattr(mod, attr_name)

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        for group_name, cmd_names in _COMMAND_GROUPS:
            rows: list[tuple[str, str]] = []
            for name in cmd_names:
                cmd = self.get_command(ctx, name)
                if cmd is None:
                    continue
                help_text = cmd.get_short_help_str(limit=formatter.width)
                rows.append((name, help_text))
            if rows:
                with formatter.section(group_name):
                    formatter.write_dl(rows)


@click.group(cls=LazyGroup, invoke_without_command=True)
@click.version_option(package_name="avakill")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """AvaKill — Open-source safety firewall for AI agents.

    Intercept tool calls. Enforce policies. Kill dangerous operations.
    """
    if ctx.invoked_subcommand is None:
        from avakill.cli.banner import print_banner

        print_banner()
        ctx.exit()
