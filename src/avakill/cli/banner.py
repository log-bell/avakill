"""AvaKill CLI startup banner."""

from rich.console import Console
from rich.text import Text


def _lerp(t, c1=(0, 212, 255), c2=(239, 68, 68)):
    """Linearly interpolate two RGB tuples; t in [0, 1]."""
    r = int(c1[0] + (c2[0] - c1[0]) * t)
    gv = int(c1[1] + (c2[1] - c1[1]) * t)
    b = int(c1[2] + (c2[2] - c1[2]) * t)
    return f"#{r:02x}{gv:02x}{b:02x}"


def _make_wordmark():
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
        # Box-drawing chars render narrower than block chars in many
        # terminals/fonts, causing visible misalignment.
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


def print_banner() -> None:
    """Print the AvaKill startup banner."""
    from importlib.metadata import version as pkg_version

    con = Console()
    tw = con.width

    try:
        ver = pkg_version("avakill")
    except Exception:
        from avakill import __version__

        ver = __version__

    con.print()

    # Wordmark — manually center so trailing whitespace doesn't
    # cause Rich's justify="center" to shift rows differently.
    lines, wm_w = _make_wordmark()
    left_pad = max(0, (tw - wm_w) // 2)
    for line in lines:
        padded = Text(" " * left_pad)
        padded.append_text(line)
        con.print(padded)

    con.print()
    con.print("the ai agent safety firewall", style="#6B7280", justify="center")
    con.print()

    sep_w = min(52, tw - 4)
    con.print("\u2500" * sep_w, style="dim #00D4FF", justify="center")

    info = Text()
    pad = max(2, sep_w - len(f"v{ver} \u03b2") - len("docs: avakill.com"))
    info.append(f"v{ver} \u03b2", style="#6B7280")
    info.append(" " * pad)
    info.append("docs: avakill.com", style="#6B7280")
    con.print(info, justify="center")
    con.print()
    con.print("run [bold]avakill --help[/bold] for commands", style="#6B7280", justify="center")
    con.print()
