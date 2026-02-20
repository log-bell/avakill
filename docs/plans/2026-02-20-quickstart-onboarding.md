# Quickstart Onboarding Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `avakill init --scan` and `avakill quickstart` to give users a single guided onboarding flow.

**Architecture:** A shared `scanner.py` module handles project introspection (sensitive files, project type detection, rule generation). The `init` command gains a `--scan` flag. A new `quickstart` command chains detection, policy generation, validation, and hook installation into one guided flow with both interactive and CLI-flag modes.

**Tech Stack:** Python 3.10+, Click (CLI), Rich (output), PyYAML, Pydantic v2 (PolicyEngine validation)

---

### Task 1: Scanner Module — Sensitive File Detection

**Files:**
- Create: `tests/test_cli_scanner.py`
- Create: `src/avakill/cli/scanner.py`

**Step 1: Write the failing tests**

```python
"""Tests for avakill.cli.scanner module."""

from __future__ import annotations

from pathlib import Path

from avakill.cli.scanner import SensitiveFile, detect_sensitive_files


class TestDetectSensitiveFiles:
    def test_detects_dotenv(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SECRET=abc")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert ".env" in paths

    def test_detects_dotenv_variants(self, tmp_path: Path) -> None:
        (tmp_path / ".env.local").write_text("X=1")
        (tmp_path / ".env.production").write_text("Y=2")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert ".env.local" in paths
        assert ".env.production" in paths

    def test_detects_pem_key_files(self, tmp_path: Path) -> None:
        (tmp_path / "server.pem").write_text("---BEGIN---")
        (tmp_path / "private.key").write_text("---KEY---")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert "server.pem" in paths
        assert "private.key" in paths

    def test_detects_credential_files(self, tmp_path: Path) -> None:
        (tmp_path / "credentials.json").write_text("{}")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert "credentials.json" in paths

    def test_detects_database_files(self, tmp_path: Path) -> None:
        (tmp_path / "app.sqlite").write_text("")
        (tmp_path / "data.db").write_text("")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert "app.sqlite" in paths
        assert "data.db" in paths

    def test_detects_credential_directories(self, tmp_path: Path) -> None:
        (tmp_path / ".aws").mkdir()
        (tmp_path / ".aws" / "credentials").write_text("")
        result = detect_sensitive_files(tmp_path)
        paths = [sf.path for sf in result]
        assert ".aws/" in paths

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        result = detect_sensitive_files(tmp_path)
        assert result == []

    def test_ignores_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / ".env").write_text("X=1")
        result = detect_sensitive_files(tmp_path)
        assert result == []

    def test_category_is_set(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("X=1")
        (tmp_path / "key.pem").write_text("---")
        result = detect_sensitive_files(tmp_path)
        categories = {sf.category for sf in result}
        assert "env" in categories
        assert "crypto" in categories
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'avakill.cli.scanner'`

**Step 3: Write minimal implementation**

```python
"""Project scanner for detecting sensitive files and project types."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}

_SENSITIVE_FILE_GLOBS: list[tuple[str, str, str]] = [
    # (glob_pattern, category, description)
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
    # (dir_name, category, description)
    (".aws", "credentials", "AWS credentials directory"),
    (".ssh", "crypto", "SSH keys directory"),
    (".gnupg", "crypto", "GPG keys directory"),
]


@dataclass(frozen=True)
class SensitiveFile:
    """A detected sensitive file or directory."""

    path: str
    category: str
    description: str


def _is_in_skip_dir(path: Path, root: Path) -> bool:
    """Check if path is inside a directory we should skip."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return any(part in _SKIP_DIRS for part in rel.parts)


def detect_sensitive_files(cwd: Path) -> list[SensitiveFile]:
    """Scan a directory for sensitive files and directories.

    Args:
        cwd: The directory to scan.

    Returns:
        List of detected sensitive files/directories.
    """
    found: list[SensitiveFile] = []
    seen: set[str] = set()

    # Check for sensitive directories
    for dir_name, category, description in _SENSITIVE_DIRS:
        candidate = cwd / dir_name
        if candidate.is_dir():
            key = f"{dir_name}/"
            if key not in seen:
                found.append(SensitiveFile(path=key, category=category, description=description))
                seen.add(key)

    # Check for sensitive files using glob patterns
    for pattern, category, description in _SENSITIVE_FILE_GLOBS:
        for match in cwd.glob(pattern):
            if match.is_file() and not _is_in_skip_dir(match, cwd):
                rel = str(match.relative_to(cwd))
                if rel not in seen:
                    found.append(SensitiveFile(path=rel, category=category, description=description))
                    seen.add(rel)

    return found
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_scanner.py -v`
Expected: PASS (all tests green)

**Step 5: Commit**

```bash
git add tests/test_cli_scanner.py src/avakill/cli/scanner.py
git commit -m "feat: add scanner module with sensitive file detection"
```

---

### Task 2: Scanner Module — Project Type Detection

**Files:**
- Modify: `tests/test_cli_scanner.py`
- Modify: `src/avakill/cli/scanner.py`

**Step 1: Write the failing tests**

Append to `tests/test_cli_scanner.py`:

```python
from avakill.cli.scanner import detect_project_type


class TestDetectProjectType:
    def test_detects_nodejs(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "test"}')
        result = detect_project_type(tmp_path)
        assert "nodejs" in result

    def test_detects_python_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]")
        result = detect_project_type(tmp_path)
        assert "python" in result

    def test_detects_python_setup_py(self, tmp_path: Path) -> None:
        (tmp_path / "setup.py").write_text("from setuptools import setup")
        result = detect_project_type(tmp_path)
        assert "python" in result

    def test_detects_rust(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").write_text("[package]")
        result = detect_project_type(tmp_path)
        assert "rust" in result

    def test_detects_go(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module example.com/test")
        result = detect_project_type(tmp_path)
        assert "go" in result

    def test_detects_swift(self, tmp_path: Path) -> None:
        (tmp_path / "Package.swift").write_text("// swift")
        result = detect_project_type(tmp_path)
        assert "swift" in result

    def test_detects_docker(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM python:3.12")
        result = detect_project_type(tmp_path)
        assert "docker" in result

    def test_detects_docker_compose(self, tmp_path: Path) -> None:
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        result = detect_project_type(tmp_path)
        assert "docker" in result

    def test_multiple_types(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]")
        (tmp_path / "Dockerfile").write_text("FROM python")
        result = detect_project_type(tmp_path)
        assert "python" in result
        assert "docker" in result

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = detect_project_type(tmp_path)
        assert result == []
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_scanner.py::TestDetectProjectType -v`
Expected: FAIL — `ImportError: cannot import name 'detect_project_type'`

**Step 3: Write minimal implementation**

Add to `src/avakill/cli/scanner.py`:

```python
_PROJECT_INDICATORS: list[tuple[list[str], str]] = [
    # (file_names_to_check, project_type)
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
    return detected
```

Also check for `.xcodeproj` directories:

```python
    # Check for Xcode projects (glob needed)
    if not any(pt == "swift" for pt in detected):
        if list(cwd.glob("*.xcodeproj")):
            detected.append("swift")
```

Insert the Xcode check right before the `return detected` line.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_scanner.py -v`
Expected: PASS (all tests green)

**Step 5: Commit**

```bash
git add tests/test_cli_scanner.py src/avakill/cli/scanner.py
git commit -m "feat: add project type detection to scanner"
```

---

### Task 3: Scanner Module — Rule Generation

**Files:**
- Modify: `tests/test_cli_scanner.py`
- Modify: `src/avakill/cli/scanner.py`

**Step 1: Write the failing tests**

Append to `tests/test_cli_scanner.py`:

```python
from avakill.cli.scanner import generate_scan_rules


class TestGenerateScanRules:
    def test_env_files_produce_deny_rule(self) -> None:
        files = [
            SensitiveFile(".env", "env", "Environment variables"),
            SensitiveFile(".env.local", "env", "Environment variables"),
        ]
        rules = generate_scan_rules(files, [])
        env_rules = [r for r in rules if r["name"] == "protect-env-files"]
        assert len(env_rules) == 1
        assert env_rules[0]["action"] == "deny"
        assert ".env" in env_rules[0]["conditions"]["args_match"]["file_path"]
        assert ".env.local" in env_rules[0]["conditions"]["args_match"]["file_path"]

    def test_crypto_files_produce_deny_rule(self) -> None:
        files = [SensitiveFile("server.pem", "crypto", "TLS cert")]
        rules = generate_scan_rules(files, [])
        crypto_rules = [r for r in rules if r["name"] == "protect-crypto-files"]
        assert len(crypto_rules) == 1
        assert crypto_rules[0]["action"] == "deny"

    def test_database_files_produce_deny_rule(self) -> None:
        files = [SensitiveFile("app.sqlite", "database", "SQLite DB")]
        rules = generate_scan_rules(files, [])
        db_rules = [r for r in rules if r["name"] == "protect-database-files"]
        assert len(db_rules) == 1
        assert db_rules[0]["action"] == "deny"

    def test_credential_files_produce_deny_rule(self) -> None:
        files = [SensitiveFile("credentials.json", "credentials", "Creds")]
        rules = generate_scan_rules(files, [])
        cred_rules = [r for r in rules if r["name"] == "protect-credential-files"]
        assert len(cred_rules) == 1

    def test_no_files_no_rules(self) -> None:
        rules = generate_scan_rules([], [])
        assert rules == []

    def test_rules_target_write_and_delete_tools(self) -> None:
        files = [SensitiveFile(".env", "env", "Env")]
        rules = generate_scan_rules(files, [])
        assert rules[0]["tools"] == ["file_write", "file_delete"]

    def test_rules_are_valid_policy_dicts(self) -> None:
        """Generated rules should be loadable by PolicyEngine."""
        files = [
            SensitiveFile(".env", "env", "Env"),
            SensitiveFile("key.pem", "crypto", "Key"),
        ]
        rules = generate_scan_rules(files, [])
        # Each rule must have name, tools, action
        for rule in rules:
            assert "name" in rule
            assert "tools" in rule
            assert "action" in rule
            assert len(rule["tools"]) >= 1
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_scanner.py::TestGenerateScanRules -v`
Expected: FAIL — `ImportError: cannot import name 'generate_scan_rules'`

**Step 3: Write minimal implementation**

Add to `src/avakill/cli/scanner.py`:

```python
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
        rules.append({
            "name": rule_name,
            "tools": ["file_write", "file_delete"],
            "action": "deny",
            "conditions": {
                "args_match": {
                    "file_path": sorted(paths),
                },
            },
            "message": message,
        })

    return rules
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_scanner.py -v`
Expected: PASS (all tests green)

**Step 5: Commit**

```bash
git add tests/test_cli_scanner.py src/avakill/cli/scanner.py
git commit -m "feat: add scan rule generation to scanner"
```

---

### Task 4: `avakill init --scan`

**Files:**
- Modify: `tests/test_cli_init.py`
- Modify: `src/avakill/cli/init_cmd.py`

**Step 1: Write the failing tests**

Append to `tests/test_cli_init.py`:

```python
import yaml


class TestInitScan:
    def test_scan_detects_env_file_and_adds_rule(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names

    def test_scan_prints_summary(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert ".env" in result.output

    def test_scan_with_no_sensitive_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()

    def test_scan_rules_come_before_template_rules(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        # Scan rules should appear before template rules
        env_idx = rule_names.index("protect-env-files")
        template_idx = rule_names.index("block-destructive-ops")
        assert env_idx < template_idx

    def test_no_scan_flag_skips_scanning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" not in rule_names

    def test_scan_detects_multiple_categories(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        (tmp_path / "server.pem").write_text("---BEGIN---")
        (tmp_path / "app.sqlite").write_text("")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names
        assert "protect-crypto-files" in rule_names
        assert "protect-database-files" in rule_names
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_init.py::TestInitScan -v`
Expected: FAIL — `No such option: --scan` (Click error)

**Step 3: Write minimal implementation**

Modify `src/avakill/cli/init_cmd.py`:

1. Add import at top:
```python
import yaml
```

2. Add `--scan` option to the `@click.command()` decorator chain:
```python
@click.option(
    "--scan/--no-scan",
    default=False,
    help="Scan project directory for sensitive files and generate targeted deny rules.",
)
```

3. Add `scan: bool` parameter to the `init()` function signature.

4. After `shutil.copy2(src, output_path)` (line 158), add scan logic:
```python
    # Scan project for sensitive files if requested
    scan_results: list[object] = []
    if scan:
        from avakill.cli.scanner import (
            detect_sensitive_files,
            detect_project_type,
            generate_scan_rules,
        )

        sensitive_files = detect_sensitive_files(Path.cwd())
        project_types = detect_project_type(Path.cwd())
        scan_rules = generate_scan_rules(sensitive_files, project_types)
        scan_results = sensitive_files  # save for summary output

        if scan_rules:
            # Read template, merge scan rules before template rules
            policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            existing_rules = policy_data.get("policies", [])
            policy_data["policies"] = scan_rules + existing_rules
            output_path.write_text(
                yaml.dump(policy_data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )
```

5. In the summary panel section, add scan results display (after the context_files block around line 177):
```python
    if scan and scan_results:
        lines.append("[bold yellow]Detected sensitive files:[/bold yellow]")
        for sf in scan_results:
            lines.append(f"  [yellow]{sf.path}[/yellow] [dim]({sf.description})[/dim]")
        lines.append("")
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_init.py -v`
Expected: PASS (all tests green, including existing tests)

**Step 5: Commit**

```bash
git add src/avakill/cli/init_cmd.py tests/test_cli_init.py
git commit -m "feat: add --scan flag to avakill init"
```

---

### Task 5: Quickstart Command — Core Flow

**Files:**
- Create: `tests/test_cli_quickstart.py`
- Create: `src/avakill/cli/quickstart_cmd.py`
- Modify: `src/avakill/cli/main.py`

**Step 1: Write the failing tests**

```python
"""Tests for avakill quickstart CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from avakill.cli.quickstart_cmd import quickstart


class TestQuickstartNonInteractive:
    """Test quickstart with all flags provided (non-interactive mode)."""

    def test_generates_policy_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()

    def test_moderate_uses_default_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "deny"

    def test_strict_uses_strict_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "strict",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        # Strict template has "allow-reads-only" as first rule
        assert any(r["name"] == "allow-reads-only" for r in policy["policies"])

    def test_permissive_uses_hooks_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "permissive",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "allow"

    def test_validation_runs_and_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        assert "Validation passed" in result.output

    def test_shows_next_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--no-scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        assert "Next steps" in result.output


class TestQuickstartWithScan:
    def test_scan_adds_rules_for_env(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names

    def test_scan_prints_detected_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--scan",
            "--output", "test.yaml",
        ])
        assert result.exit_code == 0
        assert ".env" in result.output


class TestQuickstartWithHookInstall:
    def test_installs_hook_for_agent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / "claude-settings.json"
        runner = CliRunner()
        with patch("avakill.cli.quickstart_cmd.install_hook") as mock_install:
            mock_install.return_value = type("R", (), {
                "config_path": config_path,
                "command": "avakill-hook-claude-code",
                "warnings": [],
                "smoke_test_passed": True,
            })()
            result = runner.invoke(quickstart, [
                "--agent", "claude-code",
                "--level", "moderate",
                "--no-scan",
                "--output", "test.yaml",
            ])
        assert result.exit_code == 0
        mock_install.assert_called_once_with("claude-code")
        assert "Hook installed" in result.output

    def test_agent_none_skips_hook_install(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        with patch("avakill.cli.quickstart_cmd.install_hook") as mock_install:
            result = runner.invoke(quickstart, [
                "--agent", "none",
                "--level", "moderate",
                "--no-scan",
                "--output", "test.yaml",
            ])
        assert result.exit_code == 0
        mock_install.assert_not_called()


class TestQuickstartHelp:
    def test_help_shows_usage(self):
        runner = CliRunner()
        result = runner.invoke(quickstart, ["--help"])
        assert result.exit_code == 0
        assert "quickstart" in result.output.lower() or "Quickstart" in result.output
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_quickstart.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'avakill.cli.quickstart_cmd'`

**Step 3: Write minimal implementation**

Create `src/avakill/cli/quickstart_cmd.py`:

```python
"""AvaKill quickstart command - guided onboarding flow."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from avakill.hooks.installer import detect_agents, install_hook

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_LEVEL_TO_TEMPLATE: dict[str, str] = {
    "strict": "strict",
    "moderate": "default",
    "permissive": "hooks",
}


@click.command()
@click.option(
    "--agent",
    default=None,
    help='Agent to guard (e.g. "claude-code", "cursor", "all", "none").',
)
@click.option(
    "--level",
    type=click.Choice(["strict", "moderate", "permissive"]),
    default=None,
    help="Protection level.",
)
@click.option(
    "--scan/--no-scan",
    default=None,
    help="Scan project directory for sensitive files.",
)
@click.option(
    "--output",
    default="avakill.yaml",
    help="Output path for the generated policy file.",
)
def quickstart(agent: str | None, level: str | None, scan: bool | None, output: str) -> None:
    """Guided setup for AvaKill — detect agents, generate policy, install hooks."""
    console = Console()
    is_interactive = sys.stdin.isatty()

    console.print()
    console.print("[bold]AvaKill Quickstart[/bold]")
    console.print("\u2500" * 31)

    # Step 1: Detect agents
    detected_agents = detect_agents()
    if detected_agents:
        console.print(f"Detected agents: [cyan]{', '.join(detected_agents)}[/cyan]")

    # Step 2: Choose agent
    if agent is None:
        if not is_interactive:
            raise click.UsageError("--agent is required in non-interactive mode")
        choices = detected_agents + ["all", "none"]
        if not detected_agents:
            choices = ["none"]
        from rich.prompt import Prompt

        agent = Prompt.ask(
            "Which agent do you want to guard?",
            choices=choices,
            default=detected_agents[0] if detected_agents else "none",
            console=console,
        )

    # Step 3: Choose protection level
    if level is None:
        if not is_interactive:
            raise click.UsageError("--level is required in non-interactive mode")
        from rich.prompt import Prompt

        level = Prompt.ask(
            "What protection level?",
            choices=["strict", "moderate", "permissive"],
            default="moderate",
            console=console,
        )

    # Step 4: Scan?
    if scan is None:
        if not is_interactive:
            scan = False
        else:
            from rich.prompt import Prompt

            scan_answer = Prompt.ask(
                "Scan this directory for sensitive files?",
                choices=["y", "n"],
                default="y",
                console=console,
            )
            scan = scan_answer == "y"

    # Step 5: Generate policy
    output_path = Path(output)
    template_name = _LEVEL_TO_TEMPLATE[level]
    src = _TEMPLATES_DIR / f"{template_name}.yaml"
    if not src.exists():
        raise click.ClickException(f"Template not found: {src}")

    shutil.copy2(src, output_path)

    # Merge scan rules if requested
    scan_results = []
    if scan:
        from avakill.cli.scanner import (
            detect_sensitive_files,
            detect_project_type,
            generate_scan_rules,
        )

        sensitive_files = detect_sensitive_files(Path.cwd())
        project_types = detect_project_type(Path.cwd())
        scan_rules = generate_scan_rules(sensitive_files, project_types)
        scan_results = sensitive_files

        if scan_results:
            file_names = [sf.path for sf in scan_results]
            console.print(
                f"Detected sensitive files: [yellow]{', '.join(file_names)}[/yellow]"
            )

        if scan_rules:
            policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            existing_rules = policy_data.get("policies", [])
            policy_data["policies"] = scan_rules + existing_rules
            output_path.write_text(
                yaml.dump(policy_data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )

    console.print()

    # Step 6: Validate
    policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    rule_count = len(policy_data.get("policies", []))
    try:
        from avakill.core.policy import PolicyEngine

        PolicyEngine.from_dict(policy_data)
        console.print(
            f"[green]\u2713[/green] Policy generated: [cyan]{output_path}[/cyan] ({rule_count} rules)"
        )
        console.print("[green]\u2713[/green] Validation passed")
    except Exception as exc:
        console.print(f"[red]\u2717[/red] Validation failed: {exc}")
        raise SystemExit(1) from exc

    # Step 7: Install hook
    agents_to_install: list[str] = []
    if agent and agent != "none":
        if agent == "all":
            agents_to_install = detected_agents
        else:
            agents_to_install = [agent]

    for a in agents_to_install:
        try:
            result = install_hook(a)
            console.print(f"[green]\u2713[/green] Hook installed for [cyan]{a}[/cyan]")
            for w in result.warnings:
                console.print(f"  [yellow]Warning:[/yellow] {w}")
        except KeyError:
            console.print(f"[yellow]![/yellow] Unknown agent: {a} (skipping hook install)")

    # Step 8: Next steps
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Review your policy:  [cyan]avakill review[/cyan]")
    console.print(
        f"  2. Test a tool call:    "
        f"[cyan]avakill evaluate --tool shell_exec "
        f"--args '{{\"command\": \"rm -rf /\"}}'[/cyan]"
    )
    console.print(f"  3. Approve the policy:  [cyan]avakill approve {output_path}[/cyan]")
    console.print()
```

**Step 4: Register `quickstart` in `src/avakill/cli/main.py`**

Add to `_COMMANDS` dict:
```python
    "quickstart": ("avakill.cli.quickstart_cmd", "quickstart"),
```

Add `"quickstart"` to the `"Getting Started"` group in `_COMMAND_GROUPS`:
```python
    ("Getting Started", ["quickstart", "init", "guide", "validate", "dashboard", "logs"]),
```

**Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_quickstart.py -v`
Expected: PASS (all tests green)

**Step 6: Commit**

```bash
git add src/avakill/cli/quickstart_cmd.py src/avakill/cli/main.py tests/test_cli_quickstart.py
git commit -m "feat: add avakill quickstart command"
```

---

### Task 6: Integration Test & Full Verification

**Files:**
- Modify: `tests/test_cli_quickstart.py` (add integration test)

**Step 1: Write integration test**

Append to `tests/test_cli_quickstart.py`:

```python
class TestQuickstartIntegration:
    """End-to-end test combining scan + policy generation + validation."""

    def test_full_flow_with_scan(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Set up a realistic project
        (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/db")
        (tmp_path / ".env.local").write_text("DEBUG=true")
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'")
        (tmp_path / "credentials.json").write_text("{}")
        (tmp_path / "app.sqlite").write_text("")

        runner = CliRunner()
        result = runner.invoke(quickstart, [
            "--agent", "none",
            "--level", "moderate",
            "--scan",
            "--output", "avakill.yaml",
        ])
        assert result.exit_code == 0
        assert "Validation passed" in result.output

        # Verify the generated policy is valid and has scan rules
        policy = yaml.safe_load((tmp_path / "avakill.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names
        assert "protect-credential-files" in rule_names
        assert "protect-database-files" in rule_names

        # Verify scan rules come before template rules
        env_idx = rule_names.index("protect-env-files")
        first_template = rule_names.index("block-destructive-ops")
        assert env_idx < first_template
```

**Step 2: Run full test suite**

Run: `make check`
Expected: All lint, typecheck, and tests pass.

**Step 3: Commit**

```bash
git add tests/test_cli_quickstart.py
git commit -m "test: add integration test for quickstart flow"
```

---

### Task 7: Final Verification

**Step 1:** Run `make check` — all lint, typecheck, tests pass.

**Step 2:** Manually verify:
```bash
# Test init --scan in a directory with .env
mkdir /tmp/test-scan && cd /tmp/test-scan
echo "SECRET=abc" > .env
echo '{"name":"test"}' > package.json
avakill init --scan --template default
cat avakill.yaml  # should contain protect-env-files rule

# Test quickstart --help
avakill quickstart --help

# Cleanup
rm -rf /tmp/test-scan
```

**Step 3:** Final commit if any cleanup needed.
