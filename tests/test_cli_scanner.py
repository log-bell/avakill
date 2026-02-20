"""Tests for avakill.cli.scanner module."""

from __future__ import annotations

from pathlib import Path

from avakill.cli.scanner import (
    SensitiveFile,
    detect_project_type,
    detect_sensitive_files,
    generate_scan_rules,
)


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
        files = [
            SensitiveFile(".env", "env", "Env"),
            SensitiveFile("key.pem", "crypto", "Key"),
        ]
        rules = generate_scan_rules(files, [])
        for rule in rules:
            assert "name" in rule
            assert "tools" in rule
            assert "action" in rule
            assert len(rule["tools"]) >= 1
