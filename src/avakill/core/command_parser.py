"""Compound shell command splitting for T3 bypass prevention.

Splits compound commands like ``echo foo && rm -rf /`` into individual
segments so each can be evaluated independently against policy rules.
This prevents bypass attacks where dangerous commands are hidden after
innocuous ones using shell operators (&&, ||, ;, |).
"""

from __future__ import annotations


def split_compound_command(command: str) -> list[str]:
    """Split a compound shell command into individual segments.

    Parses character-by-character, tracking quoting state (single quotes,
    double quotes, backslash escapes) and nesting depth (``$()``, backticks).
    Splits on unquoted ``&&``, ``||``, ``;``, and ``|``.  Also extracts
    inner commands from ``$()`` and backtick subshells.

    Args:
        command: The shell command string to split.

    Returns:
        A list of trimmed, non-empty command segments.
    """
    if not command:
        return []

    segments: list[str] = []
    current: list[str] = []
    subshell_commands = _extract_subshell_commands(command)

    i = 0
    length = len(command)
    in_single_quote = False
    in_double_quote = False
    escape_next = False

    while i < length:
        ch = command[i]

        # Handle backslash escape (outside single quotes)
        if escape_next:
            current.append(ch)
            escape_next = False
            i += 1
            continue

        if ch == "\\" and not in_single_quote:
            escape_next = True
            current.append(ch)
            i += 1
            continue

        # Single quote toggling (not inside double quotes)
        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(ch)
            i += 1
            continue

        # Double quote toggling (not inside single quotes)
        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(ch)
            i += 1
            continue

        # Only split on operators when not inside quotes
        if not in_single_quote and not in_double_quote:
            # Check for && (two chars)
            if ch == "&" and i + 1 < length and command[i + 1] == "&":
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                i += 2
                continue

            # Check for || (two chars) — must distinguish from single |
            if ch == "|" and i + 1 < length and command[i + 1] == "|":
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                i += 2
                continue

            # Check for single | (pipe)
            if ch == "|":
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                i += 1
                continue

            # Check for ; (semicolon)
            if ch == ";":
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                i += 1
                continue

        current.append(ch)
        i += 1

    # Final segment
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)

    # Append subshell inner commands as additional segments
    segments.extend(subshell_commands)

    return segments


def is_compound_command(command: str) -> bool:
    """Fast check for whether a command contains unquoted shell operators.

    Uses the same quoting logic as :func:`split_compound_command` but
    returns early on the first unquoted operator, avoiding a full split.

    Args:
        command: The shell command string to check.

    Returns:
        True if the command contains unquoted ``&&``, ``||``, ``;``, or ``|``.
    """
    if not command:
        return False

    i = 0
    length = len(command)
    in_single_quote = False
    in_double_quote = False
    escape_next = False

    while i < length:
        ch = command[i]

        if escape_next:
            escape_next = False
            i += 1
            continue

        if ch == "\\" and not in_single_quote:
            escape_next = True
            i += 1
            continue

        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            i += 1
            continue

        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            i += 1
            continue

        if not in_single_quote and not in_double_quote:
            # && or ||
            if ch == "&" and i + 1 < length and command[i + 1] == "&":
                return True
            if ch == "|" and i + 1 < length and command[i + 1] == "|":
                return True
            # Single |
            if ch == "|":
                return True
            # ;
            if ch == ";":
                return True

        i += 1

    # Also check for subshell commands
    return bool(_extract_subshell_commands(command))


def _extract_subshell_commands(command: str) -> list[str]:
    """Extract inner commands from ``$()`` and backtick subshells.

    Handles nested ``$()`` via depth tracking.  Does not recurse into
    backtick-nested backticks (which is undefined behaviour in most shells).

    Args:
        command: The shell command string to scan.

    Returns:
        A list of trimmed, non-empty inner command strings.
    """
    if not command:
        return []

    results: list[str] = []
    i = 0
    length = len(command)
    in_single_quote = False
    in_double_quote = False
    escape_next = False

    while i < length:
        ch = command[i]

        if escape_next:
            escape_next = False
            i += 1
            continue

        if ch == "\\" and not in_single_quote:
            escape_next = True
            i += 1
            continue

        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            i += 1
            continue

        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            i += 1
            continue

        # $() subshell — track paren depth
        if not in_single_quote and ch == "$" and i + 1 < length and command[i + 1] == "(":
            depth = 1
            start = i + 2
            j = start
            sq = False
            dq = False
            esc = False
            while j < length and depth > 0:
                c = command[j]
                if esc:
                    esc = False
                    j += 1
                    continue
                if c == "\\" and not sq:
                    esc = True
                    j += 1
                    continue
                if c == "'" and not dq:
                    sq = not sq
                elif c == '"' and not sq:
                    dq = not dq
                elif not sq and not dq:
                    if c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                j += 1
            inner = command[start : j - 1].strip() if depth == 0 else command[start:].strip()
            if inner:
                results.append(inner)
            i = j
            continue

        # Backtick subshell
        if not in_single_quote and ch == "`":
            start = i + 1
            j = start
            while j < length and command[j] != "`":
                if command[j] == "\\" and j + 1 < length:
                    j += 2
                else:
                    j += 1
            inner = command[start:j].strip()
            if inner:
                results.append(inner)
            i = j + 1
            continue

        i += 1

    return results
