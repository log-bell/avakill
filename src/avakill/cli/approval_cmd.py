"""CLI commands for managing pending approval requests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from avakill.core.approval import ApprovalStore

console = Console()


def _run(coro):  # type: ignore[no-untyped-def]
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


@click.group()
def approvals() -> None:
    """Manage pending approval requests."""


@approvals.command(name="list")
@click.option("--db", default="~/.avakill/approvals.db", help="Approval database path.")
def list_pending(db: str) -> None:
    """List pending approval requests."""
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console.print("[dim]No approval database found. No pending requests.[/]")
        return

    async def _list() -> None:
        async with ApprovalStore(db_path) as store:
            await store.cleanup_expired()
            pending = await store.get_pending()

        if not pending:
            console.print("[green]No pending approval requests.[/]")
            return

        table = Table(title="Pending Approval Requests", show_lines=True)
        table.add_column("ID", style="bold", max_width=12)
        table.add_column("Agent")
        table.add_column("Tool")
        table.add_column("Arguments", max_width=40)
        table.add_column("Policy")
        table.add_column("Timestamp")

        for req in pending:
            args_str = str(req.tool_call.arguments)
            if len(args_str) > 40:
                args_str = args_str[:37] + "..."
            table.add_row(
                req.id[:12],
                req.agent,
                req.tool_call.tool_name,
                args_str,
                req.decision.policy_name or "-",
                req.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            )
        console.print(table)

    _run(_list())


@approvals.command()
@click.argument("request_id")
@click.option("--db", default="~/.avakill/approvals.db", help="Approval database path.")
@click.option("--approver", default="cli-user", help="Name of the approver.")
def grant(request_id: str, db: str, approver: str) -> None:
    """Approve a pending request."""
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console.print("[dim]No approval requests found. No approvals have been recorded yet.[/]")
        raise SystemExit(1)

    async def _grant() -> None:
        async with ApprovalStore(db_path) as store:
            try:
                full_id = await store.resolve_id(request_id)
            except KeyError as exc:
                console.print(f"[red]{exc}[/]")
                raise SystemExit(1) from None
            if full_id is None:
                console.print(f"[red]Request not found:[/] {request_id}")
                raise SystemExit(1)
            try:
                req = await store.approve(full_id, approver=approver)
                console.print(
                    f"[green]Approved[/] request {req.id[:12]}... "
                    f"(tool={req.tool_call.tool_name}, approver={approver})"
                )
            except KeyError:
                console.print(f"[red]Request not found:[/] {request_id}")
                raise SystemExit(1) from None

    _run(_grant())


@approvals.command()
@click.argument("request_id")
@click.option("--db", default="~/.avakill/approvals.db", help="Approval database path.")
@click.option("--approver", default="cli-user", help="Name of the denier.")
def reject(request_id: str, db: str, approver: str) -> None:
    """Deny a pending request."""
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console.print("[dim]No approval requests found. No approvals have been recorded yet.[/]")
        raise SystemExit(1)

    async def _reject() -> None:
        async with ApprovalStore(db_path) as store:
            try:
                full_id = await store.resolve_id(request_id)
            except KeyError as exc:
                console.print(f"[red]{exc}[/]")
                raise SystemExit(1) from None
            if full_id is None:
                console.print(f"[red]Request not found:[/] {request_id}")
                raise SystemExit(1)
            try:
                req = await store.deny(full_id, approver=approver)
                console.print(
                    f"[red]Denied[/] request {req.id[:12]}... "
                    f"(tool={req.tool_call.tool_name}, denier={approver})"
                )
            except KeyError:
                console.print(f"[red]Request not found:[/] {request_id}")
                raise SystemExit(1) from None

    _run(_reject())
