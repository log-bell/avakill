# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.1] - 2026-02-23

### Added

- `avakill setup` — single interactive command replacing init/guide/quickstart (detect agents, create policy, install hooks, activity tracking)
- `avakill tracking on/off/status` — user-facing interface for activity tracking (wraps daemon lifecycle)
- User config management (`~/.avakill/config.json`) for tracking preferences and setup state
- UX specification document (`docs/UX.md`)

### Changed

- Self-protection deny messages now include structured agent instructions with rule name, STOP directive, and a pre-written "Tell the user:" block to relay
- Hook adapters (Claude Code, Gemini CLI, Windsurf) no longer append generic suffix to self-protection denials
- Default template changed from `default` to `hooks` in `avakill init`
- `avakill.yaml` rewritten as hooks-oriented policy with native tool names for all supported agents
- CLI banner redesigned with state-aware status display and blue-to-red gradient wordmark
- CLI command groups reorganized: `setup`, `tracking`, `fix` promoted to Getting Started

### Fixed

- mypy errors in `config.py` and `tracking_cmd.py`

## [0.5.0] - 2026-02-22

### Added

- Fail-closed mode (`AVAKILL_FAIL_CLOSED=1`) — deny tool calls when daemon is unreachable
- Gemini CLI normalization: `search_files`, `list_files`, `web_search`, `web_fetch`
- Windsurf normalization: `mcp_tool`
- Daemon `on_ready` callback for programmatic startup notification
- Codex installer auto-discovers `avakill.yaml` in cwd
- Templates: `python3` in safe commands; `web_fetch`, `search_files`, `list_files` in read-ops
- MCP filesystem write blocking in permissive template

### Changed

- Gemini CLI deny: exit code 2 + stderr (was JSON stdout + exit 0)
- Gemini CLI config path: lazy cwd-relative resolution
- Windsurf: stderr warning when `require_approval` degrades to allow
- Daemon foreground mode: prints listening address

### Fixed

- Go shim: expand `~` in socket paths
- Go shim: capture deny reason from subprocess stdout

[0.5.0]: https://github.com/log-bell/avakill/compare/v0.4.0...v0.5.0
[0.5.1]: https://github.com/log-bell/avakill/compare/v0.5.0...v0.5.1
[Unreleased]: https://github.com/log-bell/avakill/compare/v0.5.1...HEAD
