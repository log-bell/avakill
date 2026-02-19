"""Shell metacharacter detection for command safety analysis.

Detects shell metacharacters that can turn allowed commands into
arbitrary writes/execution: pipes, redirects, chaining, subshells,
variable expansion, and dangerous builtins.
"""

from __future__ import annotations

import re

# Individual metacharacter patterns with human-readable descriptions
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Pipes
    (re.compile(r"\|"), "pipe (|)"),
    # Output redirects: >, >>, note: avoid matching => or ->
    (re.compile(r"(?<![=\-])>>?(?!=)"), "output redirect (> or >>)"),
    # Input redirects: <, <<
    (re.compile(r"<<?\s"), "input redirect (< or <<)"),
    # Chaining: ;
    (re.compile(r";"), "command chaining (;)"),
    # Logical chaining: && ||
    (re.compile(r"&&"), "logical AND (&&)"),
    (re.compile(r"\|\|"), "logical OR (||)"),
    # Backtick subshell
    (re.compile(r"`"), "backtick subshell (`)"),
    # $() subshell
    (re.compile(r"\$\("), "subshell expansion ($())"),
    # ${} variable expansion
    (re.compile(r"\$\{"), "variable expansion (${})"),
    # Dangerous builtins — match as whole words
    (re.compile(r"\beval\b"), "eval builtin"),
    (re.compile(r"\bsource\b"), "source builtin"),
    (re.compile(r"\bxargs\b"), "xargs command"),
]


def is_shell_safe(command: str) -> tuple[bool, list[str]]:
    """Check whether a shell command is free of metacharacters.

    Args:
        command: The shell command string to analyse.

    Returns:
        A tuple of ``(is_safe, findings)`` where *is_safe* is ``True``
        when no metacharacters are detected and *findings* is a list of
        human-readable descriptions of what was found.
    """
    if not command:
        return True, []

    findings: list[str] = []
    for pattern, description in _PATTERNS:
        if pattern.search(command):
            findings.append(description)

    return (len(findings) == 0), findings
