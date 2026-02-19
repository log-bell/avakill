"""Agent detection and hook registration logic.

Detects which AI coding agents are installed on the system and
registers/unregisters AvaKill hooks in each agent's configuration.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


def _cursor_installed() -> bool:
    """Check if Cursor is installed."""
    if platform.system() == "Darwin":
        return Path("/Applications/Cursor.app").exists()
    return shutil.which("cursor") is not None or Path.home().joinpath(".cursor").is_dir()


def _windsurf_installed() -> bool:
    """Check if Windsurf is installed."""
    if platform.system() == "Darwin":
        return Path("/Applications/Windsurf.app").exists()
    return (
        shutil.which("windsurf") is not None
        or Path.home().joinpath(".codeium", "windsurf").is_dir()
    )


AGENT_DETECTORS: dict[str, Callable[[], bool]] = {
    "claude-code": lambda: (
        Path.home().joinpath(".claude").is_dir() or shutil.which("claude") is not None
    ),
    "gemini-cli": lambda: (
        Path.home().joinpath(".gemini").is_dir() or shutil.which("gemini") is not None
    ),
    "cursor": _cursor_installed,
    "windsurf": _windsurf_installed,
    "openclaw": lambda: (
        Path.home().joinpath(".openclaw").is_dir() or shutil.which("openclaw") is not None
    ),
    "aider": lambda: shutil.which("aider") is not None,
    "cline": lambda: Path.cwd().joinpath(".vscode", "cline_mcp_settings.json").is_file(),
    "continue": lambda: (
        Path.cwd().joinpath(".continue", "config.json").is_file()
        or Path.home().joinpath(".continue").is_dir()
    ),
    "swe-agent": lambda: shutil.which("sweagent") is not None,
}


def detect_agents() -> list[str]:
    """Return list of installed agent names."""
    return [name for name, check in AGENT_DETECTORS.items() if check()]


# ---------------------------------------------------------------------------
# Hook installation
# ---------------------------------------------------------------------------

_HOOK_COMMAND = "avakill-hook-{slug}"

# Agent-specific settings paths and hook shapes.
_AGENT_CONFIG: dict[str, dict[str, object]] = {
    "claude-code": {
        "config_path": Path.home() / ".claude" / "settings.json",
        "event": "PreToolUse",
        "hook_entry": lambda cmd: {
            "matcher": "",
            "hooks": [{"type": "command", "command": cmd}],
        },
    },
    "gemini-cli": {
        "config_path": Path.home() / ".gemini" / "settings.json",
        "event": "BeforeTool",
        "hook_entry": lambda cmd: {
            "matcher": ".*",
            "hooks": [{"type": "command", "command": cmd}],
        },
    },
    "cursor": {
        "config_path": lambda: Path.cwd() / ".cursor" / "hooks.json",
        "event": "beforeShellExecution",
        "hook_entry": lambda cmd: {"command": cmd},
    },
    "windsurf": {
        "config_path": Path.home() / ".codeium" / "windsurf" / "hooks.json",
        "event": "pre_run_command",
        "hook_entry": lambda cmd: {"command": cmd, "show_output": True},
    },
}


def _resolve_config_path(cfg: dict[str, object]) -> Path:
    """Return the config path, calling it if it's a callable (lazy eval)."""
    raw = cfg["config_path"]
    if callable(raw):
        return Path(raw())
    assert isinstance(raw, Path)
    return raw


def _hook_command(agent: str) -> str:
    """Return the absolute path to the console-script for an agent.

    Resolves via ``shutil.which()`` first.  Falls back to looking in the
    same ``bin/`` directory as the running Python interpreter (handles
    virtualenvs where the scripts aren't on ``$PATH``).  If neither
    works, returns the bare command name as a last resort.
    """
    slug = agent.replace("-", "-").replace(" ", "-")
    bare = _HOOK_COMMAND.format(slug=slug)

    # 1. Try PATH
    found = shutil.which(bare)
    if found:
        return found

    # 2. Try sibling of sys.executable (same venv)
    bin_dir = Path(sys.executable).resolve().parent
    candidate = bin_dir / bare
    if candidate.is_file():
        return str(candidate)

    # 3. Bare name — will fail at runtime but install_hook warns
    return bare


def _is_avakill_entry(entry: dict[str, object]) -> bool:
    """Check if a hook entry belongs to AvaKill."""
    # Check command field directly.
    cmd = entry.get("command", "")
    if isinstance(cmd, str) and "avakill" in cmd:
        return True
    # Check nested hooks list (Claude Code / Gemini CLI shape).
    hooks = entry.get("hooks", [])
    if isinstance(hooks, list):
        for h in hooks:
            if isinstance(h, dict) and "avakill" in str(h.get("command", "")):
                return True
    return False


class HookInstallResult:
    """Result of a hook installation with optional warnings."""

    def __init__(self, config_path: Path, command: str) -> None:
        self.config_path = config_path
        self.command = command
        self.warnings: list[str] = []
        self.smoke_test_passed: bool | None = None

    @property
    def path(self) -> Path:
        return self.config_path


def install_hook(agent: str, config_path: Path | None = None) -> HookInstallResult:
    """Register AvaKill hook in an agent's config.

    Args:
        agent: Agent name (e.g. "claude-code").
        config_path: Override the default config path (useful for testing).

    Returns:
        A :class:`HookInstallResult` with the config path, resolved
        command, and any warnings.  The result is truthy and its
        ``.config_path`` / ``.path`` attribute gives the path (backwards
        compatible with code that treats the return as a ``Path``).

    Raises:
        KeyError: If *agent* is not a known agent.
    """
    if agent not in _AGENT_CONFIG:
        raise KeyError(f"unknown agent: {agent!r}")

    cfg = _AGENT_CONFIG[agent]
    path = config_path or _resolve_config_path(cfg)
    event: str = cfg["event"]  # type: ignore[assignment]
    make_entry: Callable[[str], dict[str, object]] = cfg["hook_entry"]  # type: ignore[assignment]

    cmd = _hook_command(agent)
    result = HookInstallResult(config_path=path, command=cmd)

    # Warn if we couldn't resolve an absolute path
    if "/" not in cmd and "\\" not in cmd:
        result.warnings.append(
            f"Could not find '{cmd}' on PATH or in the active Python environment. "
            f"The hook may fail silently. Try: pip install avakill"
        )

    entry = make_entry(cmd)

    # Load or create config.
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    # Ensure hooks section exists.
    hooks = data.setdefault("hooks", {})
    event_hooks = hooks.setdefault(event, [])

    # Idempotent: don't duplicate if already present.
    if not any(_is_avakill_entry(e) for e in event_hooks):
        event_hooks.append(entry)

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    # Smoke test: verify the hook binary actually runs
    result.smoke_test_passed = _smoke_test(cmd)
    if not result.smoke_test_passed:
        result.warnings.append(
            f"Smoke test failed: '{cmd}' did not execute successfully. "
            f"Hook calls will fail at runtime."
        )

    return result


def _smoke_test(cmd: str) -> bool:
    """Run a minimal invocation of the hook binary to verify it exists.

    Sends an empty stdin — the hook should fail with a parse error (exit 2)
    rather than "command not found" (exit 127).  Any exit code other than
    127 means the binary was found and executed.
    """
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            input="",
            capture_output=True,
            timeout=5,
        )
        # exit 127 = command not found; anything else = binary exists
        return proc.returncode != 127
    except (OSError, subprocess.TimeoutExpired):
        return False


def uninstall_hook(agent: str, config_path: Path | None = None) -> bool:
    """Remove AvaKill hook from an agent's config.

    Returns:
        ``True`` if a hook was removed, ``False`` otherwise.
    """
    if agent not in _AGENT_CONFIG:
        raise KeyError(f"unknown agent: {agent!r}")

    cfg = _AGENT_CONFIG[agent]
    path = config_path or _resolve_config_path(cfg)
    event: str = cfg["event"]  # type: ignore[assignment]

    if not path.exists():
        return False

    data = json.loads(path.read_text(encoding="utf-8"))
    hooks = data.get("hooks", {})
    event_hooks = hooks.get(event, [])

    original_len = len(event_hooks)
    event_hooks[:] = [e for e in event_hooks if not _is_avakill_entry(e)]

    if len(event_hooks) == original_len:
        return False

    hooks[event] = event_hooks
    data["hooks"] = hooks
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return True


def list_installed_hooks() -> dict[str, bool]:
    """Return ``{agent: is_installed}`` for all known agents."""
    result: dict[str, bool] = {}
    for agent, cfg in _AGENT_CONFIG.items():
        path = _resolve_config_path(cfg)
        installed = False
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                event: str = cfg["event"]  # type: ignore[assignment]
                for entry in data.get("hooks", {}).get(event, []):
                    if _is_avakill_entry(entry):
                        installed = True
                        break
            except (json.JSONDecodeError, OSError):
                pass
        result[agent] = installed
    return result
