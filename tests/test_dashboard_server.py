"""Tests for dashboard server and CLI command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner


class TestDashboardCLI:
    """Tests for the avakill dashboard CLI command."""

    def test_command_exists(self) -> None:
        from avakill.cli.dashboard_cmd import dashboard

        assert dashboard is not None
        assert hasattr(dashboard, "callback")

    def test_default_port_is_7700(self) -> None:
        from avakill.cli.dashboard_cmd import dashboard

        port_param = None
        for param in dashboard.params:
            if param.name == "port":
                port_param = param
                break
        assert port_param is not None
        assert port_param.default == 7700

    def test_has_no_open_flag(self) -> None:
        from avakill.cli.dashboard_cmd import dashboard

        param_names = [p.name for p in dashboard.params]
        assert "no_open" in param_names

    @patch("avakill.cli.dashboard_cmd.asyncio")
    @patch("avakill.cli.dashboard_cmd.webbrowser")
    def test_missing_aiohttp_shows_error(self, mock_wb: MagicMock, mock_asyncio: MagicMock) -> None:
        from avakill.cli.dashboard_cmd import dashboard

        runner = CliRunner()
        with patch("avakill.cli.dashboard_cmd._check_deps") as mock_check:
            mock_check.side_effect = SystemExit(1)
            result = runner.invoke(dashboard, ["--no-open"])
            assert result.exit_code != 0
