"""T2 path resolution engine for AvaKill.

Resolves tilde (`~/`), environment variables (`$HOME`, `$USERPROFILE`),
relative paths (`../`), and symlinks before policy matching. This
prevents bypass attacks where raw argument strings like `rm -rf ~/`
pass substring matching because `~` is never expanded.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path


def resolve_path(raw: str, *, resolve_symlinks: bool = True) -> str:
    """Expand and resolve a raw path string to an absolute path.

    Expansion order: environment variables → user home (tilde) → absolute path.

    Args:
        raw: The raw path string (may contain ``~/``, ``$HOME``, ``../``, etc.).
        resolve_symlinks: If True (default), follow symlinks to the real path.
            If False, use ``os.path.abspath()`` instead.

    Returns:
        The fully resolved absolute path as a string.
    """
    if not raw or not raw.strip():
        return raw

    expanded = os.path.expandvars(raw)
    expanded = str(Path(expanded).expanduser())

    if resolve_symlinks:
        return str(Path(expanded).resolve())
    return os.path.abspath(expanded)


def is_path_like(token: str) -> bool:
    """Return True if a token looks like a filesystem path.

    Matches tokens starting with ``/``, ``~/``, ``~``, ``$HOME``,
    ``$USERPROFILE``, ``%USERPROFILE%``, ``../``, or ``./``.
    """
    if not token:
        return False
    return token.startswith(
        (
            "/",
            "~/",
            "~",
            "$HOME",
            "$USERPROFILE",
            "%USERPROFILE%",
            "../",
            "./",
        )
    )


def extract_paths_from_command(command: str) -> list[str]:
    """Extract path-like tokens from a shell command string.

    Uses ``shlex.split()`` to handle quoting correctly, falling back
    to ``str.split()`` on parse errors.

    Args:
        command: A shell command string (e.g. ``"rm -rf ~/Downloads"``).

    Returns:
        List of tokens that look like filesystem paths.
    """
    if not command or not command.strip():
        return []
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return [t for t in tokens if is_path_like(t)]


def resolve_paths_from_value(
    value: str,
    *,
    is_command: bool = False,
    resolve_symlinks: bool = True,
) -> list[str]:
    """Resolve paths from an argument value.

    Args:
        value: The raw argument value.
        is_command: If True, extract paths from the command first.
            Otherwise treat the whole value as a single path.
        resolve_symlinks: Passed through to :func:`resolve_path`.

    Returns:
        List of resolved absolute paths.
    """
    if not value or not value.strip():
        return []

    raw_paths = extract_paths_from_command(value) if is_command else [value]
    return [resolve_path(p, resolve_symlinks=resolve_symlinks) for p in raw_paths]


def path_matches_protected(resolved_path: str, protected_paths: list[str]) -> bool:
    """Check whether a resolved path falls under any protected path prefix.

    Uses ``/`` boundary matching so ``/etc/ssh`` matches ``/etc/`` but
    ``/etcetera`` does not.

    Args:
        resolved_path: A fully resolved absolute path.
        protected_paths: List of protected path prefixes (resolved).

    Returns:
        True if *resolved_path* equals or is a descendant of any protected path.
    """
    if not resolved_path:
        return False

    # Normalise: ensure trailing sep consistency
    norm = os.path.normpath(resolved_path)

    for protected in protected_paths:
        prot_norm = os.path.normpath(protected)
        # Exact match
        if norm == prot_norm:
            return True
        # Root dir: everything is a descendant of /
        if prot_norm == os.sep:
            return True
        # Descendant check: /etc/ssh starts with /etc/
        if norm.startswith(prot_norm + os.sep):
            return True

    return False


def detect_workspace_root() -> str:
    """Detect the workspace root directory.

    Priority:
    1. ``AVAKILL_WORKSPACE`` environment variable.
    2. Walk up from cwd looking for ``.git``.
    3. Fall back to ``Path.cwd()``.

    Returns:
        The workspace root as an absolute path string.
    """
    env_ws = os.environ.get("AVAKILL_WORKSPACE")
    if env_ws:
        return str(Path(env_ws).resolve())

    current = Path.cwd().resolve()
    for parent in [current, *current.parents]:
        if (parent / ".git").exists():
            return str(parent)

    return str(current)
