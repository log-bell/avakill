# Design: Interactive `avakill guide` Command

**Date**: 2026-02-20
**Status**: Approved

## Problem

AvaKill has 18 doc files covering every feature, but users don't read them. New users pick a template in `avakill init` and never customize their policy. They don't understand when to use hooks vs launch mode vs MCP proxy. The education needs to happen inside the CLI, at the moment of decision, and work for both vibe coders and senior engineers.

## Solution

A new `avakill guide` command with two modes:

- `avakill guide` — interactive protection mode wizard
- `avakill guide policy` — interactive policy creation wizard

Both use progressive disclosure: simple recommendation first (for vibe coders), trade-offs explanation below (for engineers), doc links at the bottom (for deep dives).

`avakill init` integrates the guide flow after template selection. The welcome screen (`avakill` no args) adds a "need help? avakill guide" line.

## Command Structure

### `avakill guide` (protection mode)

**Questions:**
1. What kind of agent? (coding assistant / persistent daemon / custom agent / not sure)
2. Does it have shell access? (yes / no / not sure)

**Output adapts to answers:**
- Coding assistant (Claude Code, Cursor, etc.) → hooks only, launch as optional upgrade
- Persistent daemon with shell (OpenClaw, SWE-Agent) → both layers recommended
- Custom agent, no shell → decorator/wrapper, hooks optional

**Output format (progressive disclosure):**
1. Recommendation with metaphors: "security camera" (hooks) / "locked room" (launch)
2. "Why both?" section with cooperative vs mandatory architecture explanation
3. Numbered "ready?" commands to run
4. Doc links for engineers who want more

### `avakill guide policy` (policy creation)

**Choices:**
1. Start from a template — shows plain-language comparison of all 4 templates
2. Have your AI agent write one — prompts for agent description + tools, generates tailored LLM prompt, copies to clipboard
3. Write it by hand — prints annotated minimal example + reference doc path

For option 2, reuses the existing `generate_prompt()` function from `avakill.core.schema` but wraps it in an interactive flow.

## Changes

| Component | Change |
|---|---|
| New: `src/avakill/cli/guide_cmd.py` | Interactive guide with `guide` and `guide policy` subcommands |
| `src/avakill/cli/banner.py` | Add "need help? avakill guide" to get started section |
| `src/avakill/cli/init_cmd.py` | Replace mode selector (lines 206-218) with guide integration |
| `src/avakill/cli/main.py` | Register `guide` in `_COMMANDS` and `_COMMAND_GROUPS` |

## Progressive Disclosure Pattern

Each recommendation section follows this structure:

```
── recommendation ──────────────────────────  ← vibe coder reads this
   Simple explanation with metaphor
   Layer 1: what it does + command
   Layer 2: what it does + command

── why? ────────────────────────────────────  ← engineer reads this
   Architecture explanation (cooperative vs mandatory,
   application-level vs kernel-level)

── ready? ──────────────────────────────────  ← both run this
   Numbered commands to execute
```

## Non-goals

- No web UI or browser-based guide
- No changes to existing docs (they're comprehensive, just undiscoverable)
- No new policy templates (4 is enough)
- No auto-execution of recommended commands (just show them)
