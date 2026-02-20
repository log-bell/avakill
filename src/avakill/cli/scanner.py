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


_PROJECT_INDICATORS: list[tuple[list[str], str]] = [
    (["package.json"], "nodejs"),
    (["pyproject.toml", "setup.py", "setup.cfg"], "python"),
    (["Cargo.toml"], "rust"),
    (["go.mod"], "go"),
    (["Package.swift"], "swift"),
    (["Dockerfile", "docker-compose.yml", "docker-compose.yaml"], "docker"),
]


def detect_project_type(cwd: Path) -> list[str]:
    """Detect project types based on indicator files.

    Args:
        cwd: The directory to scan.

    Returns:
        List of detected project type strings (e.g. ["python", "docker"]).
    """
    detected: list[str] = []
    for filenames, project_type in _PROJECT_INDICATORS:
        if any((cwd / fn).exists() for fn in filenames):
            detected.append(project_type)

    # Check for Xcode projects (glob needed)
    if "swift" not in detected and list(cwd.glob("*.xcodeproj")):
        detected.append("swift")

    return detected


_CATEGORY_RULE_NAMES: dict[str, str] = {
    "env": "protect-env-files",
    "crypto": "protect-crypto-files",
    "credentials": "protect-credential-files",
    "database": "protect-database-files",
}

_CATEGORY_MESSAGES: dict[str, str] = {
    "env": "Detected env file(s) — blocking write/delete by default",
    "crypto": "Detected crypto key(s) — blocking write/delete by default",
    "credentials": "Detected credential file(s) — blocking write/delete by default",
    "database": "Detected database file(s) — blocking write/delete by default",
}


def generate_scan_rules(
    sensitive_files: list[SensitiveFile],
    project_types: list[str],
) -> list[dict[str, object]]:
    """Generate deny rules for detected sensitive files.

    Groups files by category and produces one rule per category.

    Args:
        sensitive_files: Detected sensitive files from detect_sensitive_files().
        project_types: Detected project types from detect_project_type().

    Returns:
        List of rule dicts ready for YAML serialization.
    """
    if not sensitive_files:
        return []

    # Group by category
    by_category: dict[str, list[str]] = {}
    for sf in sensitive_files:
        by_category.setdefault(sf.category, []).append(sf.path)

    rules: list[dict[str, object]] = []
    for category, paths in by_category.items():
        rule_name = _CATEGORY_RULE_NAMES.get(category, f"protect-{category}-files")
        message = _CATEGORY_MESSAGES.get(
            category,
            f"Detected {category} file(s) — blocking write/delete by default",
        )
        rules.append(
            {
                "name": rule_name,
                "tools": ["file_write", "file_delete"],
                "action": "deny",
                "conditions": {
                    "args_match": {
                        "file_path": sorted(paths),
                    },
                },
                "message": message,
            }
        )

    return rules
