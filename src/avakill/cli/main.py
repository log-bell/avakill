"""AvaKill CLI entry point."""

import click


@click.group(invoke_without_command=True)
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


# Import and register subcommands
from avakill.cli.approval_cmd import approvals  # noqa: E402
from avakill.cli.approve_cmd import approve  # noqa: E402
from avakill.cli.check_hardening_cmd import check_hardening  # noqa: E402
from avakill.cli.compliance_cmd import compliance  # noqa: E402
from avakill.cli.daemon_cmd import daemon  # noqa: E402
from avakill.cli.dashboard_cmd import dashboard  # noqa: E402
from avakill.cli.enforce_cmd import enforce  # noqa: E402
from avakill.cli.evaluate_cmd import evaluate  # noqa: E402
from avakill.cli.harden_cmd import harden  # noqa: E402
from avakill.cli.hook_cmd import hook  # noqa: E402
from avakill.cli.init_cmd import init  # noqa: E402
from avakill.cli.keygen_cmd import keygen  # noqa: E402
from avakill.cli.logs_cmd import logs  # noqa: E402
from avakill.cli.mcp_proxy_cmd import mcp_proxy  # noqa: E402
from avakill.cli.metrics_cmd import metrics  # noqa: E402
from avakill.cli.review_cmd import review  # noqa: E402
from avakill.cli.schema_cmd import schema  # noqa: E402
from avakill.cli.sign_cmd import sign  # noqa: E402
from avakill.cli.validate_cmd import validate  # noqa: E402
from avakill.cli.verify_cmd import verify  # noqa: E402

cli.add_command(approve)
cli.add_command(approvals)
cli.add_command(check_hardening)
cli.add_command(compliance)
cli.add_command(daemon)
cli.add_command(enforce)
cli.add_command(evaluate)
cli.add_command(harden)
cli.add_command(hook)
cli.add_command(init)
cli.add_command(dashboard)
cli.add_command(keygen)
cli.add_command(logs)
cli.add_command(mcp_proxy)
cli.add_command(metrics)
cli.add_command(review)
cli.add_command(schema)
cli.add_command(sign)
cli.add_command(validate)
cli.add_command(verify)
