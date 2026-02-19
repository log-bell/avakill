"""Tests for the ``avakill metrics`` CLI command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from avakill.cli.main import cli


class TestMetricsCommand:
    def test_help_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["metrics", "--help"])
        assert result.exit_code == 0
        assert "Prometheus" in result.output
        assert "--port" in result.output
        assert "--host" in result.output

    def test_requires_prometheus_client(self) -> None:
        """With prometheus installed, the help text should be accessible."""
        runner = CliRunner()
        result = runner.invoke(cli, ["metrics", "--help"])
        assert result.exit_code == 0

    def test_mock_server_start(self) -> None:
        runner = CliRunner()
        mock_event = MagicMock()
        mock_event.wait.side_effect = KeyboardInterrupt()

        with (
            patch("avakill.cli.metrics_cmd.threading.Event", return_value=mock_event),
            patch("prometheus_client.start_http_server") as mock_start,
        ):
            runner.invoke(cli, ["metrics", "--port", "9100"])
            assert mock_start.called
            assert mock_start.call_args[0][0] == 9100

    def test_mock_server_custom_host_and_port(self) -> None:
        """Verify start_http_server is called with custom host and port."""
        runner = CliRunner()
        mock_event = MagicMock()
        mock_event.wait.side_effect = KeyboardInterrupt()

        with (
            patch("avakill.cli.metrics_cmd.threading.Event", return_value=mock_event),
            patch("prometheus_client.start_http_server") as mock_start,
        ):
            runner.invoke(cli, ["metrics", "--port", "9200", "--host", "127.0.0.1"])
            assert mock_start.called
            assert mock_start.call_args[0][0] == 9200
            assert mock_start.call_args[1]["addr"] == "127.0.0.1"
