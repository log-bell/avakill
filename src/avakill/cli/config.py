"""AvaKill user config management (~/.avakill/config.json)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_CONFIG_PATH = Path.home() / ".avakill" / "config.json"
_DEFAULT_AUDIT_DB = "~/.avakill/audit.db"


def _read() -> dict[str, object]:
    """Read the config file, returning {} if missing or corrupt."""
    if not _CONFIG_PATH.exists():
        return {}
    try:
        data: dict[str, object] = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def _write(data: dict[str, object]) -> None:
    """Write the config file."""
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def is_tracking_enabled() -> bool:
    """Return True if the user opted into activity tracking."""
    return bool(_read().get("tracking_enabled", False))


def get_audit_db_path() -> str:
    """Return the configured audit DB path."""
    return str(_read().get("audit_db", _DEFAULT_AUDIT_DB))


def get_protection_level() -> str | None:
    """Return the protection level chosen during setup."""
    level = _read().get("protection_level")
    return str(level) if level is not None else None


def set_tracking(enabled: bool) -> None:
    """Update the tracking_enabled preference."""
    data = _read()
    data["tracking_enabled"] = enabled
    _write(data)


def mark_setup(*, protection_level: str) -> None:
    """Record that setup was completed."""
    data = _read()
    data["setup_complete"] = True
    data["setup_date"] = datetime.now(timezone.utc).isoformat()
    data["protection_level"] = protection_level
    if "audit_db" not in data:
        data["audit_db"] = _DEFAULT_AUDIT_DB
    _write(data)


def get_config() -> dict:
    """Return a copy of the full config."""
    return _read()
