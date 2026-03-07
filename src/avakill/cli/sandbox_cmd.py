"""CLI command group for OS sandbox operations."""

from __future__ import annotations

from pathlib import Path

import click


@click.group()
def sandbox() -> None:
    """OS-level sandbox tools.

    \b
        avakill sandbox verify --policy avakill.yaml
    """


@sandbox.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
def verify(policy: str) -> None:
    """Verify that OS sandbox restrictions are working.

    Loads the policy, generates the SBPL profile, and runs quick tests
    inside the sandbox to confirm that disallowed operations are blocked
    and allowed operations succeed.
    """
    import subprocess
    import sys
    import tempfile

    import yaml
    from rich.console import Console

    from avakill.core.models import PolicyConfig

    console = Console()

    # 1. Load policy
    policy_path = Path(policy)
    if not policy_path.exists():
        console.print(f"  [red]\u2717[/red] Policy file not found: {policy}")
        raise SystemExit(1)

    try:
        data = yaml.safe_load(policy_path.read_text())
        config = PolicyConfig.model_validate(data)
    except Exception as exc:
        console.print(f"  [red]\u2717[/red] Failed to load policy: {exc}")
        raise SystemExit(1) from None

    # 2. Check for sandbox section
    if config.sandbox is None:
        console.print("  [red]\u2717[/red] No 'sandbox:' section in policy.")
        console.print("    Add one with [cyan]avakill setup[/cyan] or manually.")
        raise SystemExit(1)

    sandbox_cfg = config.sandbox

    # 3. Check platform
    if sys.platform != "darwin":
        console.print(
            f"  [yellow]\u26a0[/yellow] Sandbox verify only supports macOS"
            f" (current: {sys.platform})"
        )
        raise SystemExit(1)

    # 4. Generate profile
    from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

    backend = MacOSSandboxBackend(config)
    if not backend.available():
        console.print("  [red]\u2717[/red] sandbox-exec not available on this system.")
        raise SystemExit(1)

    profile_content = backend.get_profile_content()

    # Generate -D params for sandbox-exec
    from avakill.launcher.backends.darwin_sbpl import generate_sbpl_params

    sbpl_params = generate_sbpl_params(sandbox_cfg)

    console.print()
    console.print("  [bold]Sandbox verification[/bold]")
    console.print()

    # Write profile to temp file
    with tempfile.NamedTemporaryFile(
        suffix=".sb", prefix="avakill-verify-", delete=False, mode="w"
    ) as f:
        f.write(profile_content)
        profile_path = f.name

    passed = 0
    failed = 0

    try:
        # Build -D args list
        d_args: list[str] = []
        for key, value in sbpl_params.items():
            d_args.extend(["-D", f"{key}={value}"])

        # Test 1: Write to disallowed path (expect failure)
        disallowed = "/usr/local/avakill-verify-test-file"
        result = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", profile_path, *d_args, "/usr/bin/touch", disallowed],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            console.print(
                f"  [green]\u2713[/green] Write to disallowed path blocked"
                f"  [dim]({disallowed})[/dim]"
            )
            passed += 1
        else:
            console.print(
                f"  [red]\u2717[/red] Write to disallowed path ALLOWED  [dim]({disallowed})[/dim]"
            )
            failed += 1
            Path(disallowed).unlink(missing_ok=True)

        # Test 2: Read from allowed path (expect success)
        allowed_read = "/usr/bin/true"
        result = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", profile_path, *d_args, "/bin/cat", allowed_read],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            console.print(
                "  [green]\u2713[/green] Read from allowed path succeeded"
                f"  [dim]({allowed_read})[/dim]"
            )
            passed += 1
        else:
            console.print(
                f"  [red]\u2717[/red] Read from allowed path FAILED  [dim]({allowed_read})[/dim]"
            )
            failed += 1

        # Test 3: Write to allowed path (expect success)
        if sandbox_cfg.allow_paths.write:
            write_dir = sandbox_cfg.allow_paths.write[0]
            test_file = str(Path(write_dir).expanduser().resolve() / ".avakill-verify-test")
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", profile_path, *d_args, "/usr/bin/touch", test_file],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                console.print(
                    "  [green]\u2713[/green] Write to allowed path succeeded"
                    f"  [dim]({test_file})[/dim]"
                )
                passed += 1
                Path(test_file).unlink(missing_ok=True)
            else:
                console.print(
                    f"  [red]\u2717[/red] Write to allowed path FAILED  [dim]({test_file})[/dim]"
                )
                failed += 1
        else:
            console.print(
                "  [yellow]\u26a0[/yellow] No write paths configured, skipping write test"
            )

    except subprocess.TimeoutExpired:
        console.print("  [red]\u2717[/red] Test timed out")
        failed += 1
    except Exception as exc:
        console.print(f"  [red]\u2717[/red] Test error: {exc}")
        failed += 1
    finally:
        Path(profile_path).unlink(missing_ok=True)

    # Summary
    console.print()
    if failed == 0:
        console.print(f"  [bold green]All {passed} tests passed.[/bold green] Sandbox is working.")
    else:
        console.print(f"  [bold red]{failed} test(s) failed[/bold red], {passed} passed.")
        raise SystemExit(1)
