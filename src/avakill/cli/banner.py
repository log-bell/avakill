"""AvaKill CLI startup banner with state-aware status display."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.text import Text

_SETUP_MARKER = Path.home() / ".avakill" / ".setup-complete"


def _lerp(
    t: float,
    c1: tuple[int, int, int] = (0, 212, 255),
    c2: tuple[int, int, int] = (239, 68, 68),
) -> str:
    """Linearly interpolate two RGB tuples; t in [0, 1]."""
    r = int(c1[0] + (c2[0] - c1[0]) * t)
    gv = int(c1[1] + (c2[1] - c1[1]) * t)
    b = int(c1[2] + (c2[2] - c1[2]) * t)
    return f"#{r:02x}{gv:02x}{b:02x}"


def _make_wordmark() -> tuple[list[Text], int]:
    """Render AVAKILL with spacing and blue-to-red gradient."""
    try:
        import pyfiglet

        fig = pyfiglet.Figlet(font="ansi_shadow")
        letters = "AVAKILL"
        cols = []
        for ch in letters:
            raw = fig.renderText(ch).rstrip("\n").split("\n")
            w = len(raw[0]) if raw else 0
            cols.append((raw, w))

        max_rows = max(len(rows) for rows, _ in cols)
        gap = 2

        joined = []
        for r in range(max_rows):
            parts = []
            for rows, w in cols:
                cell = rows[r] if r < len(rows) else ""
                parts.append(cell.ljust(w))
            joined.append((" " * gap).join(parts))

        while joined and not joined[-1].strip():
            joined.pop()

        # Replace box-drawing chars so only block and space are used.
        sanitized = []
        for line in joined:
            line = line.replace("\u2551", "\u2588")  # ║ -> █
            line = line.replace("\u2554", "\u2588")  # ╔ -> █
            line = line.replace("\u2557", "\u2588")  # ╗ -> █
            line = line.replace("\u255a", " ")  # ╚ -> space
            line = line.replace("\u255d", " ")  # ╝ -> space
            line = line.replace("\u2550", " ")  # ═ -> space
            sanitized.append(line)
        joined = sanitized

        total_w = max(len(line) for line in joined) if joined else 1
        out = []
        for line in joined:
            if not line.strip():
                continue
            t = Text()
            for i, ch in enumerate(line):
                if ch.strip():
                    frac = i / max(total_w - 1, 1)
                    t.append(ch, style=f"bold {_lerp(frac)}")
                else:
                    t.append(ch)
            out.append(t)
        return out, total_w

    except Exception:
        pass

    # Fallback when pyfiglet is not installed
    word = "A  V  A  K  I  L  L"
    t = Text()
    for i, ch in enumerate(word):
        if ch != " ":
            t.append(ch, style=f"bold {_lerp(i / max(len(word) - 1, 1))}")
        else:
            t.append(" ")
    return [t], len(word)


def _get_version() -> str:
    from importlib.metadata import version as pkg_version

    try:
        return pkg_version("avakill")
    except Exception:
        from avakill import __version__

        return __version__


def _print_header(con: Console) -> None:
    """Print wordmark + tagline."""
    tw = con.width
    ver = _get_version()

    con.print()

    lines, wm_w = _make_wordmark()
    left_pad = max(0, (tw - wm_w) // 2)
    for line in lines:
        padded = Text(" " * left_pad)
        padded.append_text(line)
        con.print(padded)

    con.print()

    tagline = Text()
    tagline.append(f"v{ver}", style="bold #00D4FF")
    tagline.append(" \u2014 the ai agent safety firewall", style="#6B7280")
    con.print(tagline, justify="center")


def _print_get_started(con: Console) -> None:
    """Print the 'not yet set up' view."""
    con.print()
    con.print("  [bold]Get started:[/bold]")
    con.print()
    cmd = Text()
    cmd.append("    avakill setup", style="bold #00D4FF")
    cmd.append("     Set up AvaKill for your AI agents", style="#6B7280")
    con.print(cmd)
    cmd2 = Text()
    cmd2.append("    avakill --help", style="bold #00D4FF")
    cmd2.append("    See all commands", style="#6B7280")
    con.print(cmd2)
    con.print()


def _get_event_count() -> str | None:
    """Return a brief event count string from the audit DB, or None."""
    import contextlib
    import sqlite3

    from avakill.cli.config import get_audit_db_path

    db_path = Path(get_audit_db_path()).expanduser()
    if not db_path.exists():
        return None
    with contextlib.suppress(Exception):
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT COUNT(*) FROM audit_events")
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            return None
        return f"{count:,} events"
    return None


def _find_policy() -> tuple[Path | None, str | None, int]:
    """Find the active policy file and return (path, template_name, rule_count)."""
    import contextlib

    import yaml

    from avakill.core.cascade import PolicyCascade

    cascade = PolicyCascade()
    discovered = cascade.discover()

    if not discovered:
        return None, None, 0

    # Use the first project-level policy, or whatever is found
    policy_path = discovered[-1][1]  # last = most local

    template_name = None
    rule_count = 0
    with contextlib.suppress(Exception):
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            rule_count = len(raw.get("policies", []))
            default_action = raw.get("default_action", "deny")
            template_name = "hooks" if default_action == "allow" else "default"

    return policy_path, template_name, rule_count


def _print_status(con: Console) -> None:
    """Print the status dashboard for already-set-up users."""
    from avakill.cli.config import is_tracking_enabled
    from avakill.daemon.server import DaemonServer
    from avakill.hooks.installer import detect_agents, list_installed_hooks

    con.print()
    con.print("  [bold]Status:[/bold]")

    # Policy
    policy_path, template_name, rule_count = _find_policy()
    if policy_path:
        policy_text = Text()
        policy_text.append("    Policy     ", style="dim")
        policy_text.append(str(policy_path.name), style="#00D4FF")
        detail_parts = []
        if template_name:
            detail_parts.append(template_name)
        detail_parts.append(f"{rule_count} rule{'s' if rule_count != 1 else ''}")
        policy_text.append(f" ({', '.join(detail_parts)})", style="#6B7280")
        con.print(policy_text)
    else:
        policy_text = Text()
        policy_text.append("    Policy     ", style="dim")
        policy_text.append("none", style="yellow")
        policy_text.append("  run ", style="#6B7280")
        policy_text.append("avakill setup", style="bold #00D4FF")
        con.print(policy_text)

    # Tracking (replaces daemon)
    running, pid = DaemonServer.is_running()
    enabled = is_tracking_enabled()
    tracking_text = Text()
    tracking_text.append("    Tracking   ", style="dim")
    if running:
        # Try to get event count from audit DB
        event_hint = _get_event_count()
        if event_hint:
            tracking_text.append(
                f"enabled ({event_hint} logged)",
                style="green",
            )
        else:
            tracking_text.append("enabled", style="green")
    elif enabled:
        tracking_text.append("not running", style="yellow")
        tracking_text.append(
            "  avakill tracking on",
            style="#6B7280",
        )
    else:
        tracking_text.append("off", style="#6B7280")
    con.print(tracking_text)

    # Hooks
    detected = detect_agents()
    installed = list_installed_hooks()

    if detected:
        hooks_text = Text()
        hooks_text.append("    Hooks      ", style="dim")
        for i, agent in enumerate(detected):
            if i > 0:
                hooks_text.append("  ")
            is_installed = installed.get(agent, False)
            if is_installed:
                hooks_text.append(
                    f"{agent} \u2713",
                    style="green",
                )
            else:
                hooks_text.append(
                    f"{agent} \u2717",
                    style="#6B7280",
                )
        con.print(hooks_text)
    else:
        hooks_text = Text()
        hooks_text.append("    Hooks      ", style="dim")
        hooks_text.append("no agents detected", style="#6B7280")
        con.print(hooks_text)

    # Commands
    con.print()
    con.print("  [bold]Commands:[/bold]")
    commands = [
        ("avakill logs", "View recent activity"),
        ("avakill dashboard", "Live monitoring"),
        ("avakill fix", "Diagnose a block"),
        ("avakill --help", "See all commands"),
    ]
    for cmd_name, desc in commands:
        row = Text()
        row.append(f"    {cmd_name:<21s}", style="bold #00D4FF")
        row.append(desc, style="#6B7280")
        con.print(row)
    con.print()


def is_setup_complete() -> bool:
    """Check if AvaKill setup has been completed."""
    return _SETUP_MARKER.exists()


def mark_setup_complete() -> None:
    """Mark AvaKill setup as complete."""
    _SETUP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    _SETUP_MARKER.write_text(_get_version())


def print_banner() -> None:
    """Print the AvaKill startup banner with state-aware content."""
    con = Console()

    _print_header(con)

    if is_setup_complete():
        _print_status(con)
    else:
        _print_get_started(con)
