"""Tests that optional extras are properly declared in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


@pytest.fixture(scope="module")
def extras() -> dict[str, list[str]]:
    with open(PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    return data["project"]["optional-dependencies"]


class TestOptionalExtras:
    def test_otel_extra_declared(self, extras: dict[str, list[str]]) -> None:
        assert "otel" in extras
        deps = extras["otel"]
        assert any("opentelemetry-api" in d for d in deps)

    def test_metrics_extra_declared(self, extras: dict[str, list[str]]) -> None:
        assert "metrics" in extras
        deps = extras["metrics"]
        assert any("prometheus-client" in d for d in deps)

    def test_all_includes_otel(self, extras: dict[str, list[str]]) -> None:
        assert "avakill[otel]" in extras["all"]

    def test_all_includes_metrics(self, extras: dict[str, list[str]]) -> None:
        assert "avakill[metrics]" in extras["all"]

    def test_dev_includes_otel_sdk(self, extras: dict[str, list[str]]) -> None:
        dev = extras["dev"]
        assert any("opentelemetry-sdk" in d for d in dev)

    def test_dev_includes_prometheus(self, extras: dict[str, list[str]]) -> None:
        dev = extras["dev"]
        assert any("prometheus-client" in d for d in dev)
