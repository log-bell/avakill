"""CLI command for launching processes inside an OS-level sandbox."""

from __future__ import annotations

from pathlib import Path

import click


@click.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--agent", default=None, help="Agent profile name (e.g. openclaw, aider).")
@click.option("--pty/--no-pty", default=False, help="Allocate PTY for interactive agents.")
@click.option("--dry-run", is_flag=True, help="Show sandbox restrictions without launching.")
@click.option("--timeout", type=int, default=None, help="Kill child after N seconds.")
@click.option(
    "--keep-profile",
    is_flag=True,
    help="Save the generated sandbox profile for inspection.",
)
@click.argument("command", nargs=-1, required=False)
def launch(
    policy: str,
    agent: str | None,
    pty: bool,
    dry_run: bool,
    timeout: int | None,
    keep_profile: bool,
    command: tuple[str, ...],
) -> None:
    """Launch a process inside an OS-level sandbox.

    Everything after -- is the command to run:

    \b
        avakill launch --policy hardened.yaml -- openclaw start
        avakill launch --agent openclaw
        avakill launch --agent aider -- aider --model gpt-4
        avakill launch --dry-run --agent openclaw

    Exit codes: Propagates the child's exit code. 126 = sandbox setup failed.
    """
    import yaml

    from avakill.core.models import PolicyConfig

    # Load agent profile if --agent is specified
    profile = None
    if agent is not None:
        from avakill.profiles.loader import load_profile

        try:
            profile = load_profile(agent)
        except FileNotFoundError as exc:
            click.echo(f"Error: {exc}", err=True)
            raise SystemExit(1) from None

    # Resolve command: CLI args override profile default
    cmd_list = list(command) if command else []
    if not cmd_list and profile is not None:
        cmd_list = profile.agent.command
    if not cmd_list and not dry_run:
        click.echo(
            "Error: no command specified. Use -- <command> or --agent with a default.", err=True
        )
        raise SystemExit(1)

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

    # If policy has no sandbox section and profile provides one, use the profile's
    if config.sandbox is None and profile is not None:
        config = config.model_copy(update={"sandbox": profile.sandbox})

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

    import sys as _sys

    from avakill.launcher.core import ProcessLauncher

    launcher = ProcessLauncher(policy=config)

    # Configure --keep-profile on the macOS sandbox backend
    if _sys.platform == "darwin" and hasattr(launcher._backend, "set_keep_profile"):
        launcher._backend.set_keep_profile(keep_profile)

    if dry_run:
        result = launcher.launch(cmd_list or ["echo", "dry-run"], dry_run=True)

        # On macOS with sandbox-exec, show the generated SBPL profile
        sbpl_profile = result.sandbox_features.get("sbpl_profile")
        if sbpl_profile:
            click.echo("Generated sandbox-exec profile (.sb):")
            click.echo(sbpl_profile)
            return

        click.echo("Sandbox dry-run report:")
        if profile:
            click.echo(f"  Agent profile: {profile.agent.name}")
        fs_avail = result.sandbox_features.get("filesystem", False)
        click.echo(f"  Platform sandbox available: {fs_avail}")
        click.echo(f"  Features: {result.sandbox_features}")
        if config.sandbox:
            click.echo(f"  Allowed read paths: {config.sandbox.allow_paths.read}")
            click.echo(f"  Allowed write paths: {config.sandbox.allow_paths.write}")
            click.echo(f"  Allowed executables: {config.sandbox.allow_paths.execute}")
            click.echo(f"  Allowed network: {config.sandbox.allow_network.connect}")
        elif not fs_avail:
            click.echo("  Note: No sandbox section in policy and no --agent specified.")
            click.echo("  Use --agent <name> to load a profile with sandbox paths,")
            click.echo("  or add a 'sandbox:' section to your policy file.")
        click.echo(f"  Command: {cmd_list}")
        return

    try:
        result = launcher.launch(cmd_list, pty=pty)
    except Exception as exc:
        click.echo(f"Error: sandbox setup failed: {exc}", err=True)
        raise SystemExit(126) from None

    # Show profile path if --keep-profile was used
    if keep_profile and hasattr(launcher._backend, "profile_path"):
        profile_path_val = launcher._backend.profile_path
        if profile_path_val:
            click.echo(f"Sandbox profile saved: {profile_path_val}", err=True)

    # Translate sandbox-specific exit codes
    if result.exit_code == 126:
        click.echo(
            "Error: sandbox-exec failed to apply the profile. "
            "Check that the .sb profile syntax is valid.",
            err=True,
        )
    elif result.exit_code == 127:
        click.echo(
            "Error: command not found inside sandbox. The sandbox may be blocking the executable.",
            err=True,
        )
    elif result.exit_code < 0:
        signum = -result.exit_code
        if signum == 9:  # SIGKILL
            click.echo(
                "Process was killed (SIGKILL). The sandbox may have blocked an operation.",
                err=True,
            )

    raise SystemExit(result.exit_code)
