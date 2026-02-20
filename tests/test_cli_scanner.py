"""Tests for avakill.cli.scanner module."""

from __future__ import annotations

from pathlib import Path

from avakill.cli.scanner import detect_project_type, detect_sensitive_files


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
