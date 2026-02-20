#!/usr/bin/env python3
"""Bump the avakill version in pyproject.toml and CHANGELOG.md."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def validate_version(v: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+", v):
        raise argparse.ArgumentTypeError(f"Invalid version: {v!r} (expected X.Y.Z)")
    return v


def bump_pyproject(new_version: str, *, dry_run: bool) -> str | None:
    text = PYPROJECT.read_text()
    pattern = r'(version\s*=\s*")([^"]+)(")'
    match = re.search(pattern, text)
    if not match:
        print(f"ERROR: Could not find version in {PYPROJECT}", file=sys.stderr)
        sys.exit(1)

    old_version = match.group(2)
    if old_version == new_version:
        print(f"  pyproject.toml already at {new_version}, skipping")
        return old_version

    updated = re.sub(pattern, rf"\g<1>{new_version}\3", text, count=1)
    if not dry_run:
        PYPROJECT.write_text(updated)
    print(f"  pyproject.toml: {old_version} -> {new_version}")
    return old_version


def bump_changelog(new_version: str, old_version: str | None, *, dry_run: bool) -> None:
    if not CHANGELOG.exists():
        print("  CHANGELOG.md not found, skipping")
        return

    text = CHANGELOG.read_text()
    today = date.today().isoformat()

    # Add new version section under [Unreleased]
    unreleased_header = "## [Unreleased]"
    if unreleased_header not in text:
        print("  CHANGELOG.md: no [Unreleased] section found, skipping")
        return

    new_section = f"{unreleased_header}\n\n## [{new_version}] - {today}"
    text = text.replace(unreleased_header, new_section)

    # Update compare links at the bottom
    repo = "https://github.com/log-bell/avakill"
    old_unreleased_link = re.search(r"\[Unreleased\]:\s*\S+", text)
    if old_unreleased_link:
        text = text.replace(
            old_unreleased_link.group(),
            f"[Unreleased]: {repo}/compare/v{new_version}...HEAD",
        )

    # Add version compare link if old_version is known
    if old_version and old_version != new_version:
        version_link = f"[{new_version}]: {repo}/compare/v{old_version}...v{new_version}"
        # Insert before the last version link
        last_bracket_link = text.rfind("\n[")
        if last_bracket_link != -1:
            text = text[:last_bracket_link] + f"\n{version_link}" + text[last_bracket_link:]

    if not dry_run:
        CHANGELOG.write_text(text)
    print(f"  CHANGELOG.md: added [{new_version}] - {today}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bump avakill version")
    parser.add_argument("version", type=validate_version, help="New version (X.Y.Z)")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing"
    )
    args = parser.parse_args()

    mode = " (dry run)" if args.dry_run else ""
    print(f"Bumping to {args.version}{mode}:\n")

    old_version = bump_pyproject(args.version, dry_run=args.dry_run)
    bump_changelog(args.version, old_version, dry_run=args.dry_run)

    print("\nDone. Next steps:")
    print("  git add pyproject.toml CHANGELOG.md")
    print(f'  git commit -m "chore: bump version to {args.version}"')
    print(f"  git tag v{args.version}")
    print("  git push && git push --tags")


if __name__ == "__main__":
    main()
