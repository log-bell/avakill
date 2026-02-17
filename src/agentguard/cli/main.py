"""AgentGuard CLI entry point."""

import click


@click.group()
@click.version_option(package_name="agentguard")
def cli() -> None:
    """AgentGuard - Safety firewall for AI agents.

    Intercept tool calls. Enforce policies. Prevent disasters.
    """
    pass


# Import and register subcommands
from agentguard.cli.dashboard_cmd import dashboard  # noqa: E402
from agentguard.cli.init_cmd import init  # noqa: E402
from agentguard.cli.logs_cmd import logs  # noqa: E402
from agentguard.cli.mcp_proxy_cmd import mcp_proxy  # noqa: E402
from agentguard.cli.validate_cmd import validate  # noqa: E402

cli.add_command(init)
cli.add_command(dashboard)
cli.add_command(logs)
cli.add_command(mcp_proxy)
cli.add_command(validate)
