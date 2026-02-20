# Design: Quickstart Onboarding (`avakill init --scan` + `avakill quickstart`)

**Date**: 2026-02-20
**Status**: Approved

## Problem

No single "do this first" flow exists. Users must piece together init, schema, write file, validate, review, approve by trial and error. Also, `avakill init` generates a generic policy with no awareness of the current project's sensitive files or project type.

## Architecture

Two features share a common scanner module:

```
init_cmd.py  ──┐
               ├──► scanner.py (shared)
quickstart_cmd.py ─┘   │
                        ├── detect_sensitive_files()
                        ├── detect_project_type()
                        └── generate_scan_rules()
```

## Feature 1: `avakill init --scan`

Add `--scan` flag to the existing `init()` command. When set, introspects the project directory before generating the policy.

### Scanner Module (`src/avakill/cli/scanner.py`)

**`detect_sensitive_files(cwd: Path) -> list[SensitiveFile]`**

Scans for common secret/config patterns using glob:
- `.env`, `.env.*` — environment variables
- `*.pem`, `*.key`, `*.p12`, `*.keystore` — crypto keys
- `credentials.json`, `serviceAccountKey.json`, `secrets.yaml` — service credentials
- `.aws/`, `.ssh/`, `.gnupg/` — credential directories
- `*.sqlite`, `*.db` — database files

Returns a dataclass: `SensitiveFile(path, category, description)`.

**`detect_project_type(cwd: Path) -> list[str]`**

Checks for language/framework indicators:
- `package.json` → `nodejs`
- `pyproject.toml` / `setup.py` → `python`
- `Cargo.toml` → `rust`
- `go.mod` → `go`
- `*.xcodeproj` / `Package.swift` → `swift`
- `Dockerfile` / `docker-compose.yml` → `docker`

**`generate_scan_rules(sensitive_files, project_types) -> list[dict]`**

Produces YAML-ready rule dicts. Rules are grouped by category (one deny rule per category, not per file). Example:

```yaml
- name: protect-env-files
  tools: ["file_write", "file_delete"]
  action: deny
  conditions:
    args_match:
      file_path: [".env"]
  message: "Detected .env file — blocking write/delete by default"
```

### Integration with init

After copying the template, if `--scan` is set:
1. Run scanner
2. Print summary of detected files and project types
3. Merge generated deny rules into the YAML (inserted before existing rules so they take priority)
4. Write the combined policy

## Feature 2: `avakill quickstart`

New guided command that chains the full setup flow. Supports both interactive prompts and CLI flags.

### CLI Flags

All optional — prompts interactively when missing in TTY, errors when missing in non-TTY:

- `--agent` — which agent to guard (detected agent name, or "all")
- `--level` — `strict` / `moderate` / `permissive`
- `--scan` / `--no-scan` — whether to run project scanning
- `--output` — output path (default `avakill.yaml`)

### Level Mapping

| Level | Template | Description |
|-------|----------|-------------|
| `strict` | `strict.yaml` | Deny-by-default, explicit allowlist only |
| `moderate` | `default.yaml` | Balanced security with common-sense defaults |
| `permissive` | `hooks.yaml` | Allow-by-default, block catastrophic ops |

### Flow

1. Detect agents via `detect_agents()`
2. Prompt/use flag for agent selection
3. Prompt/use flag for protection level
4. Prompt/use flag for scan
5. Generate policy: copy template + merge scan rules if requested
6. Validate: programmatically call `PolicyEngine.from_dict()` (no subprocess)
7. Install hook via `install_hook()` if agent was selected
8. Print Rich-formatted summary with next steps

### Output Format

```
AvaKill Quickstart
───────────────────────────────
Detected agents: claude-code, cursor
Detected sensitive files: .env, .env.local, credentials.json

✓ Policy generated: avakill.yaml (12 rules)
✓ Validation passed
✓ Hook installed for claude-code

Next steps:
  1. Review your policy:  avakill review
  2. Test a tool call:    avakill evaluate --tool shell_exec --args '{"command": "rm -rf /"}'
  3. Approve the policy:  avakill approve avakill.yaml
```

## Files Changed/Created

| File | Change |
|------|--------|
| `src/avakill/cli/scanner.py` | **New** — scanning logic |
| `src/avakill/cli/quickstart_cmd.py` | **New** — quickstart command |
| `src/avakill/cli/init_cmd.py` | Add `--scan` flag, integrate scanner |
| `src/avakill/cli/main.py` | Register `quickstart` command |
| `tests/test_cli_scanner.py` | **New** — scanner tests |
| `tests/test_cli_quickstart.py` | **New** — quickstart tests |
| `tests/test_cli_init.py` | Add `--scan` tests |
