# Plan: Full Release Pipeline for PyPI Publishing

## Context

The project has an existing release workflow (`.github/workflows/release.yml`) that publishes to PyPI on `v*` tags using trusted publisher (OIDC). However it has no safety gates — it doesn't run tests, doesn't validate versions, and doesn't create a GitHub Release. We need to harden this into a proper release pipeline.

## Current State

- **CI workflow** (`.github/workflows/ci.yml`): runs lint/typecheck/tests on push to main and PRs. Works.
- **Release workflow** (`.github/workflows/release.yml`): triggers on `v*` tags, just builds + publishes. No tests, no version check, no GitHub Release.
- **Version lives in two places**: `pyproject.toml` line 7 and `src/avakill/__init__.py` line 7.

## Changes

### File: `.github/workflows/release.yml` (rewrite)

Replace the existing workflow with a 3-job pipeline:

**Job 1: `validate`**
- Extract version from the tag (strip `v` prefix)
- Read version from `pyproject.toml`
- Fail if they don't match (prevents publishing wrong version)

**Job 2: `test`**
- Needs: `validate`
- Reuse the CI workflow via `workflow_call`, OR run tests inline
- Since `ci.yml` doesn't currently support `workflow_call`, we'll run tests inline (single Python 3.12 on ubuntu — full matrix already ran on the PR/push)

**Job 3: `publish`**
- Needs: `test`
- Build with `python -m build`
- Publish to PyPI via `pypa/gh-action-pypi-publish@release/v1` (trusted publisher, already configured)
- Create a GitHub Release with auto-generated release notes

### Permissions

- `id-token: write` — PyPI trusted publisher OIDC
- `contents: write` — creating GitHub Releases

## Files to Modify

1. `.github/workflows/release.yml` — rewrite with 3 jobs

## Verification

1. Read the final workflow YAML and check syntax
2. Simulate: does a tag like `v0.3.0` with matching `pyproject.toml` version pass validation?
3. Confirm the existing `id-token: write` permission is preserved for trusted publisher
4. Confirm the GitHub Release step uses the tag for the release name
