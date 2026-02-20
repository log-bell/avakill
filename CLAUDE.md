# AvaKill

## Release Process

Version is single-sourced from `pyproject.toml` via `importlib.metadata`. Never hardcode versions elsewhere.

```bash
# 1. Bump version (updates pyproject.toml, CHANGELOG.md, site/index.html, welcome-email.mjml, uv.lock)
python scripts/bump-version.py X.Y.Z

# 2. Commit & tag
git add -A
git commit -m "chore: bump version to X.Y.Z"
git tag vX.Y.Z

# 3. Push (triggers release.yml)
git push && git push --tags
```

CI then automatically: builds wheel, validates tag matches `pyproject.toml`, smoke tests the wheel, publishes to PyPI (trusted publishing), and creates a GitHub Release.
