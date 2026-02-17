.PHONY: install dev test lint format typecheck clean build publish publish-test check

install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

test:
	pytest

test-cov:
	pytest --cov=agentguard --cov-report=term-missing

lint:
	ruff check src tests

format:
	ruff format src tests

typecheck:
	mypy src

check: lint typecheck test
	@echo "All checks passed."

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/

build: clean
	python -m build

publish-test: build
	twine upload --repository testpypi dist/*

publish: build
	twine upload dist/*

# ─── Publishing Checklist ───────────────────────────────────────────
#
# 1. Update version in pyproject.toml and src/agentguard/__init__.py
# 2. Run:  make check          (lint + typecheck + tests)
# 3. Run:  make build           (creates dist/)
# 4. Run:  make publish-test    (upload to TestPyPI first)
# 5. Verify: pip install -i https://test.pypi.org/simple/ agentguard
# 6. Run:  make publish         (upload to PyPI)
#
# Requires ~/.pypirc or TWINE_USERNAME/TWINE_PASSWORD env vars.
# Example ~/.pypirc:
#
#   [distutils]
#   index-servers =
#       pypi
#       testpypi
#
#   [pypi]
#   username = __token__
#   password = pypi-<your-api-token>
#
#   [testpypi]
#   username = __token__
#   password = pypi-<your-test-api-token>
#
# ─────────────────────────────────────────────────────────────────────
