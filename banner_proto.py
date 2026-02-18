#!/usr/bin/env python3
"""AvaKill CLI Banner Prototype v3 — wordmark only, no head."""

import sys
from rich.console import Console
from rich.text import Text


# ─── Gradient helper ────────────────────────────────────────────────────

def _lerp(t, c1=(0, 212, 255), c2=(239, 68, 68)):
    """Linearly interpolate two RGB tuples; t ∈ [0, 1]."""
    r = int(c1[0] + (c2[0] - c1[0]) * t)
    gv = int(c1[1] + (c2[1] - c1[1]) * t)
    b = int(c1[2] + (c2[2] - c1[2]) * t)
    return f"#{r:02x}{gv:02x}{b:02x}"


# ─── Wordmark ───────────────────────────────────────────────────────────

def _make_wordmark():
    """Render AVAKILL with spacing and blue→red gradient."""
    try:
        import pyfiglet

        # Render each letter individually, then join with a fixed-width gap.
        fig = pyfiglet.Figlet(font="ansi_shadow")
        letters = "AVAKILL"
        cols = []  # list of (column_strings_per_row, width)
        for ch in letters:
            raw = fig.renderText(ch).rstrip("\n").split("\n")
            w = len(raw[0]) if raw else 0
            cols.append((raw, w))

        max_rows = max(len(rows) for rows, _ in cols)
        gap = 2

        # Build each output row by concatenating fixed-width columns + gap
        joined = []
        for r in range(max_rows):
            parts = []
            for rows, w in cols:
                cell = rows[r] if r < len(rows) else ""
                parts.append(cell.ljust(w))
            joined.append((" " * gap).join(parts))

        # Drop trailing blank rows
        while joined and not joined[-1].strip():
            joined.pop()

        # Replace box-drawing chars so only █ and space are used.
        # Box-drawing chars (╚═╝╔╗║) render narrower than █ in many
        # terminals/fonts, causing visible misalignment.
        sanitized = []
        for line in joined:
            line = line.replace("║", "█").replace("╔", "█").replace("╗", "█")
            line = line.replace("╚", " ").replace("╝", " ").replace("═", " ")
            sanitized.append(line)
        joined = sanitized

        # Apply gradient.  Return raw strings — caller handles centering.
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

    # fallback — plain styled text
    word = "A  V  A  K  I  L  L"
    t = Text()
    for i, ch in enumerate(word):
        if ch != " ":
            t.append(ch, style=f"bold {_lerp(i / max(len(word) - 1, 1))}")
        else:
            t.append(" ")
    return [t], len(word)


# ─── Print the full banner ─────────────────────────────────────────────

def print_banner():
    con = Console()
    tw = con.width

    con.print()

    # 1) Wordmark — manually center so trailing whitespace doesn't
    #    cause Rich's justify="center" to shift rows differently.
    lines, wm_w = _make_wordmark()
    left_pad = max(0, (tw - wm_w) // 2)
    for line in lines:
        padded = Text(" " * left_pad)
        padded.append_text(line)
        con.print(padded)

    # 2) Subtitle
    con.print()
    con.print("the ai agent safety firewall", style="#6B7280", justify="center")
    con.print()

    # 3) Separator
    sep_w = min(52, tw - 4)
    con.print("─" * sep_w, style="dim #00D4FF", justify="center")

    # 4) Version / docs
    info = Text()
    pad = max(2, sep_w - len("v0.1.0 β") - len("docs: avakill.com"))
    info.append("v0.1.0 β", style="#6B7280")
    info.append(" " * pad)
    info.append("docs: avakill.com", style="#6B7280")
    con.print(info, justify="center")
    con.print()


if __name__ == "__main__":
    print_banner()
