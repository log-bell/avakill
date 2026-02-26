"""Tests for dashboard data collectors."""

from __future__ import annotations

from pathlib import Path


class TestGitCollector:
    """Tests for collect_git_state()."""

    def test_returns_branch_name(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "branch" in result
        assert isinstance(result["branch"], str)

    def test_returns_head_sha(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "head_sha" in result

    def test_returns_dirty_flag(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "dirty" in result
        assert isinstance(result["dirty"], bool)

    def test_returns_file_lists(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "staged" in result
        assert "modified" in result
        assert "untracked" in result
        assert isinstance(result["staged"], list)

    def test_returns_recent_commits(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "recent_commits" in result
        assert isinstance(result["recent_commits"], list)

    def test_returns_stashes(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_git_state

        result = collect_git_state(tmp_path)
        assert "stashes" in result

    def test_works_on_real_repo(self) -> None:
        """Integration test using the actual avakill repo."""
        from avakill.cli.dashboard_cmd import collect_git_state

        root = Path(__file__).resolve().parent.parent
        result = collect_git_state(root)
        assert len(result["branch"]) > 0
        assert len(result["head_sha"]) >= 7
