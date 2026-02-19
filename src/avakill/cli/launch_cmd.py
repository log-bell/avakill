"""CLI command for launching processes inside an OS-level sandbox."""

from __future__ import annotations

from pathlib import Path

import click


@click.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--pty/--no-pty", default=False, help="Allocate PTY for interactive agents.")
@click.option("--dry-run", is_flag=True, help="Show sandbox restrictions without launching.")
@click.option("--timeout", type=int, default=None, help="Kill child after N seconds.")
@click.argument("command", nargs=-1, required=True)
def launch(
    policy: str,
    pty: bool,
    dry_run: bool,
    timeout: int | None,
    command: tuple[str, ...],
) -> None:
    """Launch a process inside an OS-level sandbox.

    Everything after -- is the command to run:

    \b
        avakill launch --policy hardened.yaml -- openclaw start
        avakill launch -- python my_agent.py
        avakill launch --dry-run -- aider --model gpt-4

    Exit codes: Propagates the child's exit code. 126 = sandbox setup failed.
    """
    import yaml

    from avakill.core.models import PolicyConfig

    policy_path = Path(policy)
    if not policy_path.exists():
        click.echo(f"Error: policy file not found: {policy}", err=True)
        raise SystemExit(1)

    try:
        data = yaml.safe_load(policy_path.read_text())
        config = PolicyConfig.model_validate(data)
    except Exception as exc:
        click.echo(f"Error: failed to load policy: {exc}", err=True)
        raise SystemExit(1) from None

    # Apply timeout override from CLI
    if timeout is not None:
        from avakill.core.models import SandboxConfig, SandboxResourceLimits

        if config.sandbox is None:
            limits = SandboxResourceLimits(timeout_seconds=timeout)
            config = config.model_copy(update={"sandbox": SandboxConfig(resource_limits=limits)})
        else:
            new_limits = config.sandbox.resource_limits.model_copy(
                update={"timeout_seconds": timeout}
            )
            new_sandbox = config.sandbox.model_copy(update={"resource_limits": new_limits})
            config = config.model_copy(update={"sandbox": new_sandbox})

    from avakill.launcher.core import ProcessLauncher

    launcher = ProcessLauncher(policy=config)

    if dry_run:
        result = launcher.launch(list(command), dry_run=True)
        click.echo("Sandbox dry-run report:")
        fs_avail = result.sandbox_features.get("filesystem", False)
        click.echo(f"  Platform sandbox available: {fs_avail}")
        click.echo(f"  Features: {result.sandbox_features}")
        if config.sandbox:
            click.echo(f"  Allowed read paths: {config.sandbox.allow_paths.read}")
            click.echo(f"  Allowed write paths: {config.sandbox.allow_paths.write}")
            click.echo(f"  Allowed executables: {config.sandbox.allow_paths.execute}")
            click.echo(f"  Allowed network: {config.sandbox.allow_network.connect}")
        click.echo(f"  Command: {list(command)}")
        return

    try:
        result = launcher.launch(list(command), pty=pty)
    except Exception as exc:
        click.echo(f"Error: sandbox setup failed: {exc}", err=True)
        raise SystemExit(126) from None

    raise SystemExit(result.exit_code)
