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


class TestModuleCollector:
    """Tests for collect_module_graph()."""

    def test_returns_nodes_and_edges(self) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        root = Path(__file__).resolve().parent.parent
        result = collect_module_graph(root / "src" / "avakill")
        assert "nodes" in result
        assert "edges" in result
        assert "subpackages" in result

    def test_nodes_have_required_fields(self) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        root = Path(__file__).resolve().parent.parent
        result = collect_module_graph(root / "src" / "avakill")
        assert len(result["nodes"]) > 0
        node = result["nodes"][0]
        assert "id" in node
        assert "path" in node
        assert "loc" in node
        assert "type" in node

    def test_edges_have_from_and_to(self) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        root = Path(__file__).resolve().parent.parent
        result = collect_module_graph(root / "src" / "avakill")
        if result["edges"]:
            edge = result["edges"][0]
            assert "from" in edge
            assert "to" in edge

    def test_detects_core_subpackage(self) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        root = Path(__file__).resolve().parent.parent
        result = collect_module_graph(root / "src" / "avakill")
        assert "core" in result["subpackages"]

    def test_engine_imports_models(self) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        root = Path(__file__).resolve().parent.parent
        result = collect_module_graph(root / "src" / "avakill")
        edges = result["edges"]
        engine_to_models = any(
            e["from"] == "core.engine" and e["to"] == "core.models" for e in edges
        )
        assert engine_to_models, "core.engine should import core.models"

    def test_skips_non_python_files(self, tmp_path: Path) -> None:
        from avakill.cli.dashboard_cmd import collect_module_graph

        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "readme.md").write_text("not python")
        (pkg / "module.py").write_text("x = 1\n")
        result = collect_module_graph(pkg)
        ids = [n["id"] for n in result["nodes"]]
        assert "module" in ids
        assert "readme" not in ids
