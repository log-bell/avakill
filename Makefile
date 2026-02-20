.PHONY: install dev test lint format typecheck clean build publish publish-test check

# Auto-detect uv availability
UV := $(shell command -v uv 2>/dev/null)
ifdef UV
  RUN := uv run
  SYNC := uv sync
else
  RUN :=
  SYNC := pip install
endif

install:
ifdef UV
	uv sync --locked
else
	pip install -e .
endif

dev:
ifdef UV
	uv sync --locked --all-extras --dev
else
	pip install -e ".[dev]"
	pre-commit install
endif

test:
	$(RUN) pytest

test-cov:
	$(RUN) pytest --cov=avakill --cov-report=term-missing

lint:
	$(RUN) ruff check src tests

format:
	$(RUN) ruff format src tests

typecheck:
	$(RUN) mypy src

check: lint typecheck test
	@echo "All checks passed."

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/

build: check clean
ifdef UV
	uv build
else
	python -m build
endif

publish-test: build
ifdef UV
	uv publish --index testpypi
else
	twine upload --repository testpypi dist/*
endif

publish: build
ifdef UV
	uv publish
else
	twine upload dist/*
endif

# ─── Release Process ──────────────────────────────────────────────
#
# 1. Bump version:  python scripts/bump-version.py X.Y.Z
# 2. Commit & tag:  git add -A && git commit -m "chore: bump version to X.Y.Z"
#                   git tag vX.Y.Z
# 3. Push:          git push && git push --tags
# 4. CI handles:    build → validate tag → smoke test → PyPI → GitHub Release
#
# ──────────────────────────────────────────────────────────────────
