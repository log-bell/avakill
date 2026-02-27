"""Tests for avakill.core.path_resolution — T2 path resolution engine."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from avakill.core.path_resolution import (
    detect_workspace_root,
    extract_paths_from_command,
    is_path_like,
    path_matches_protected,
    resolve_path,
    resolve_paths_from_value,
)


class TestResolvePath:
    """Tests for resolve_path()."""

    def test_tilde_expansion(self):
        result = resolve_path("~/Downloads")
        assert result == str(Path.home() / "Downloads")

    @pytest.mark.skipif(sys.platform == "win32", reason="$HOME not set on Windows")
    def test_home_env_var(self):
        result = resolve_path("$HOME/.ssh")
        expected = str(Path(os.environ["HOME"]) / ".ssh")
        assert result == expected

    def test_dotdot_resolution(self, tmp_path, monkeypatch):
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        monkeypatch.chdir(sub)
        result = resolve_path("../")
        assert result == str((tmp_path / "a").resolve())

    def test_symlink_resolution(self, tmp_path):
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real_dir)
        result = resolve_path(str(link))
        assert result == str(real_dir.resolve())

    def test_symlink_no_resolve(self, tmp_path):
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real_dir)
        result = resolve_path(str(link), resolve_symlinks=False)
        assert "link" in result

    def test_absolute_path_unchanged(self):
        result = resolve_path("/usr/local/bin")
        assert result == str(Path("/usr/local/bin").resolve())

    def test_empty_string(self):
        assert resolve_path("") == ""

    def test_whitespace_only(self):
        assert resolve_path("   ") == "   "

    def test_nonexistent_path(self):
        result = resolve_path("~/nonexistent_dir_xyz_12345")
        assert str(Path.home()) in result


class TestIsPathLike:
    """Tests for is_path_like()."""

    def test_absolute_path(self):
        assert is_path_like("/etc/passwd") is True

    def test_tilde_slash(self):
        assert is_path_like("~/Downloads") is True

    def test_tilde_alone(self):
        assert is_path_like("~") is True

    def test_home_env(self):
        assert is_path_like("$HOME/.ssh") is True

    def test_userprofile_env(self):
        assert is_path_like("$USERPROFILE/Documents") is True

    def test_userprofile_percent(self):
        assert is_path_like("%USERPROFILE%\\Documents") is True

    def test_dotdot_slash(self):
        assert is_path_like("../../../etc") is True

    def test_dot_slash(self):
        assert is_path_like("./build") is True

    def test_not_path_like(self):
        assert is_path_like("hello") is False
        assert is_path_like("-rf") is False
        assert is_path_like("rm") is False

    def test_empty(self):
        assert is_path_like("") is False


class TestExtractPathsFromCommand:
    """Tests for extract_paths_from_command()."""

    def test_rm_rf_home(self):
        paths = extract_paths_from_command("rm -rf ~/Downloads")
        assert paths == ["~/Downloads"]

    def test_rm_rf_root(self):
        paths = extract_paths_from_command("rm -rf /")
        assert paths == ["/"]

    def test_quoted_path(self):
        paths = extract_paths_from_command('rm -rf "~/my folder"')
        assert paths == ["~/my folder"]

    def test_no_paths(self):
        paths = extract_paths_from_command("echo hello")
        assert paths == []

    def test_multiple_paths(self):
        paths = extract_paths_from_command("cp ~/a ~/b")
        assert paths == ["~/a", "~/b"]

    def test_empty_command(self):
        assert extract_paths_from_command("") == []

    def test_whitespace_only(self):
        assert extract_paths_from_command("   ") == []

    def test_malformed_quotes_fallback(self):
        # shlex.split raises ValueError on unbalanced quotes
        paths = extract_paths_from_command('rm -rf "~/unterminated')
        # Falls back to str.split, won't find path-like tokens due to quote prefix
        assert isinstance(paths, list)

    def test_env_var_path(self):
        paths = extract_paths_from_command("rm -rf $HOME/Downloads")
        assert paths == ["$HOME/Downloads"]

    def test_dotdot_path(self):
        paths = extract_paths_from_command("cat ../../../etc/passwd")
        assert paths == ["../../../etc/passwd"]


class TestResolvePathsFromValue:
    """Tests for resolve_paths_from_value()."""

    def test_command_mode(self):
        results = resolve_paths_from_value("rm -rf ~/Downloads", is_command=True)
        assert len(results) == 1
        assert str(Path.home() / "Downloads") in results[0]

    def test_path_mode(self):
        results = resolve_paths_from_value("~/Downloads")
        assert len(results) == 1
        assert str(Path.home() / "Downloads") in results[0]

    def test_empty_value(self):
        assert resolve_paths_from_value("") == []

    def test_whitespace_value(self):
        assert resolve_paths_from_value("   ") == []

    def test_command_no_paths(self):
        results = resolve_paths_from_value("echo hello", is_command=True)
        assert results == []


class TestPathMatchesProtected:
    """Tests for path_matches_protected()."""

    def test_exact_match(self):
        assert path_matches_protected("/etc", ["/etc"]) is True

    def test_descendant_match(self):
        assert path_matches_protected("/etc/ssh/config", ["/etc"]) is True

    def test_no_match(self):
        assert path_matches_protected("/home/user/code", ["/etc"]) is False

    def test_prefix_boundary(self):
        # /etcetera should NOT match /etc
        assert path_matches_protected("/etcetera", ["/etc"]) is False

    def test_multiple_protected(self):
        protected = ["/etc", "/usr", "/boot"]
        assert path_matches_protected("/usr/local/bin", protected) is True
        assert path_matches_protected("/home/user", protected) is False

    def test_trailing_slash(self):
        assert path_matches_protected("/etc/ssh", ["/etc/"]) is True

    def test_empty_path(self):
        assert path_matches_protected("", ["/etc"]) is False

    def test_home_dir(self):
        home = str(Path.home())
        assert path_matches_protected(f"{home}/.ssh/id_rsa", [home]) is True


class TestDetectWorkspaceRoot:
    """Tests for detect_workspace_root()."""

    def test_env_var_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AVAKILL_WORKSPACE", str(tmp_path))
        assert detect_workspace_root() == str(tmp_path.resolve())

    def test_git_root(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AVAKILL_WORKSPACE", raising=False)
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "src" / "pkg"
        sub.mkdir(parents=True)
        monkeypatch.chdir(sub)
        assert detect_workspace_root() == str(tmp_path.resolve())

    def test_fallback_to_cwd(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AVAKILL_WORKSPACE", raising=False)
        monkeypatch.chdir(tmp_path)
        # No .git anywhere in tmp_path hierarchy (within the tmp dir itself)
        result = detect_workspace_root()
        # Result should be a valid absolute path
        assert os.path.isabs(result)
