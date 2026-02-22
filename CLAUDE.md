# AvaKill

## Release Process

Version is single-sourced from `pyproject.toml` via `importlib.metadata`. Never hardcode versions elsewhere.

```bash
# 1. Verify lint, typecheck, and tests all pass
make check

# 2. Update CHANGELOG.md — move [Unreleased] items into a new [X.Y.Z] section
# Follow Keep a Changelog format: Added, Changed, Fixed, Removed

# 3. Check README.md for necessary updates — new features, removed features,
# CLI commands, roadmap status, and supported agents should match what's shipping

# 3b. Check docs/ for necessary updates — verify against source code:
#   - docs/getting-started.md
#   - docs/api-reference.md
#   - docs/cli-reference.md
#   - docs/policy-reference.md
#   - docs/cookbook.md

# 3c. Decide whether to send an update email to contributors/subscribers.
#   Use this matrix — find your change type (row) and audience impact (column):
#
#                        All users       Specific integrations   No user impact
#   Breaking change      SEND            SEND (targeted)         SEND
#   New feature          SEND            SEND (targeted)         SKIP
#   Security fix         SEND            SEND                    SEND
#   Bug fix              CONSIDER        SEND (targeted)         SKIP
#   Deprecation          SEND            SEND (targeted)         SKIP
#   Docs-only            SKIP            SKIP                    SKIP
#   Internal/chore       SKIP            SKIP                    SKIP
#
#   SEND            = always email
#   SEND (targeted) = email users of affected integration
#   CONSIDER        = email if significant or frequently reported
#   SKIP            = no email needed

# 4. Bump version (updates pyproject.toml, CHANGELOG.md, site/index.html, welcome-email.mjml, uv.lock)
python scripts/bump-version.py X.Y.Z

# 5. Commit (no tag yet)
git add -A
git commit -m "chore: bump version to X.Y.Z"

# 6. Push and wait for CI to pass
git push
# Fix any CI failures, amend or add commits as needed, push again

# 7. Tag only after CI is green (triggers release.yml)
git tag vX.Y.Z
git push --tags
```

CI then automatically: builds wheel, validates tag matches `pyproject.toml`, smoke tests the wheel, publishes to PyPI (trusted publishing), and creates a GitHub Release.
