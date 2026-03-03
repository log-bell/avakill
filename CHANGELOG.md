# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
