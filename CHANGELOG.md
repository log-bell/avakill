# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-03-07

### Added
- **macOS SBPL sandbox rewrite** — deny-default sandbox profiles using scoped writes + broad reads baseline, replacing the previous allow-based model
- **`SandboxDenyPaths` model** — sensitive path denials (`~/.ssh`, `~/.aws`, `~/.gnupg`, etc.) now configurable via `deny_paths.read` in policy
- **`avakill sandbox verify`** — verify sandbox enforcement with 3 automated tests (disallowed write blocked, allowed read works, allowed write works)
- **Linux Landlock CI smoke tests** — 5 automated tests on ubuntu-latest confirming Landlock enforcement works end-to-end
- **Windows AppContainer CI smoke tests** — 4 automated tests on windows-latest confirming sandbox enforcement
- **Sandbox recipes** in `docs/cookbook.md` — setup, preview, debug, customize, and test sandbox workflows
- **Sandbox tab** on landing page quick start terminal

### Changed
- `sandbox-exec` invocation now uses `-D` parameter substitution for dynamic paths instead of string interpolation in SBPL profiles
- Default sandbox config simplified — removed binary resolution, uses deny-default model across all platforms
- CLI help text for `launch`, `sandbox`, and `setup` commands now explains deny-default model and troubleshooting
- Template YAML files (`default.yaml`, `strict.yaml`) now include annotated sandbox configuration comments
- Documentation (`policy-reference.md`, `cli-reference.md`, `getting-started.md`) updated to reflect shipped sandbox status — removed all "future release" labels
- Removed Tetragon/Kubernetes from shipped sandbox feature descriptions (README, landing page)

### Fixed
- **Landlock `available()` always returned False on Linux** — was creating an empty ruleset with `handled_access_fs=0` which the kernel rejects; now uses `abi_version() > 0` query
- **Landlock integration tests failed on Linux** — execute paths didn't include `/usr/lib` for the dynamic linker; widened from `/usr/bin` to `/usr`
- **macOS `sandbox-exec` `-D` argument ordering** — parameters must come before the profile flag
- **SBPL profile regex** — fixed pattern matching for deny path expressions
- **Root read access** in SBPL profiles — added literal root read rule for sandbox-exec

## [1.1.0] - 2026-03-03

### Added
- **AMP hook adapter** — support for Amazon Q Developer (AMP) agent hooks
- **Kiro hook adapter** — support for AWS Kiro agent hooks
- **Rage mode** — humorous denial messages (`avakill rage on/off`, `AVAKILL_RAGE=1`)
- **Shared audit logging** — MCP proxy standalone evaluations now write to `~/.avakill/audit.db`, fixing `avakill logs` showing nothing for proxy blocks
- **`avakill rage` CLI command** — toggle rage mode on/off
- Privacy policy page on marketing site

### Changed
- Extracted `try_log_to_audit_db()` into `avakill.logging.standalone` as a shared helper for hooks and MCP proxy
- Improved Cursor hook adapter with updated config handling
- Updated hook installer to support AMP and Kiro agents
- Policy engine deny reasons now include rage messages when rage mode is enabled

### Fixed
- MCP proxy guard-mode and policy-mode decisions now appear in `avakill logs`
- Removed broken lazy-config-path tests for Cursor and Gemini (configs are global, not per-project)

## [1.0.0] - 2026-02-27
