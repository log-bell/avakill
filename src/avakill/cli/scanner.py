"""AvaKill scanner - detect sensitive files in a project directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS: set[str] = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

_SENSITIVE_FILE_GLOBS: list[tuple[str, str, str]] = [
    (".env", "env", "Environment variables"),
    (".env.*", "env", "Environment variables"),
    ("*.pem", "crypto", "TLS/SSL certificate or key"),
    ("*.key", "crypto", "Private key"),
    ("*.p12", "crypto", "PKCS#12 keystore"),
    ("*.keystore", "crypto", "Java keystore"),
    ("credentials.json", "credentials", "Service credentials"),
    ("serviceAccountKey.json", "credentials", "GCP service account key"),
    ("secrets.yaml", "credentials", "Secrets file"),
    ("secrets.yml", "credentials", "Secrets file"),
    ("*.sqlite", "database", "SQLite database"),
    ("*.db", "database", "Database file"),
]

_SENSITIVE_DIRS: list[tuple[str, str, str]] = [
    (".aws", "credentials", "AWS credentials directory"),
    (".ssh", "crypto", "SSH keys directory"),
    (".gnupg", "crypto", "GPG keys directory"),
]


@dataclass(frozen=True)
class SensitiveFile:
    """A sensitive file detected in a project directory."""

    path: str
    category: str
    description: str


def _is_in_skip_dir(file_path: Path, cwd: Path) -> bool:
    """Check whether a file resides under any directory in _SKIP_DIRS."""
    try:
        rel = file_path.relative_to(cwd)
    except ValueError:
        return False
    return any(part in _SKIP_DIRS for part in rel.parts)


def detect_sensitive_files(cwd: Path) -> list[SensitiveFile]:
    """Scan *cwd* for sensitive files and directories.

    Returns a list of :class:`SensitiveFile` instances.  Directories in
    :data:`_SENSITIVE_DIRS` are reported with a trailing ``/`` in the path.
    Files inside :data:`_SKIP_DIRS` are ignored.  Duplicates are
    suppressed via a ``seen`` set.
    """
    results: list[SensitiveFile] = []
    seen: set[str] = set()

    # Check for sensitive directories first
    for dir_name, category, description in _SENSITIVE_DIRS:
        candidate = cwd / dir_name
        if candidate.is_dir():
            rel_path = f"{dir_name}/"
            if rel_path not in seen:
                seen.add(rel_path)
                results.append(
                    SensitiveFile(path=rel_path, category=category, description=description)
                )

    # Glob for sensitive files
    for glob_pattern, category, description in _SENSITIVE_FILE_GLOBS:
        for match in cwd.rglob(glob_pattern):
            if not match.is_file():
                continue
            if _is_in_skip_dir(match, cwd):
                continue
            rel_path = str(match.relative_to(cwd))
            if rel_path not in seen:
                seen.add(rel_path)
                results.append(
                    SensitiveFile(path=rel_path, category=category, description=description)
                )

    return results
