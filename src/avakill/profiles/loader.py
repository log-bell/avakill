"""Agent profile discovery and loading."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from avakill.core.exceptions import ConfigError
from avakill.profiles.models import AgentProfile

logger = logging.getLogger("avakill.profiles")

_BUILTIN_DIR = Path(__file__).resolve().parent


def get_builtin_profile_dir() -> Path:
    """Return the directory containing built-in agent profiles."""
    return _BUILTIN_DIR


def list_profiles() -> list[str]:
    """Return names of all available built-in agent profiles."""
    profiles = []
    for f in sorted(_BUILTIN_DIR.glob("*.yaml")):
        profiles.append(f.stem)
    return profiles


def load_profile(source: str | Path) -> AgentProfile:
    """Load an agent profile from a name or path.

    Args:
        source: Either a built-in profile name (e.g. "openclaw")
            or a path to a YAML file.

    Returns:
        A validated AgentProfile.

    Raises:
        FileNotFoundError: If the profile cannot be found.
        ConfigError: If the YAML is invalid.
    """
    path = _resolve_profile_path(source)
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if data is None:
            data = {}
        return AgentProfile.model_validate(data)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in profile {path}: {exc}") from exc
    except ValidationError as exc:
        raise ConfigError(f"Invalid profile in {path}: {exc}") from exc


def _resolve_profile_path(source: str | Path) -> Path:
    """Resolve a profile source to an actual file path."""
    path = Path(source)
    if path.is_file():
        return path

    builtin = _BUILTIN_DIR / f"{source}.yaml"
    if builtin.is_file():
        return builtin

    user_dir = Path.home() / ".config" / "avakill" / "profiles"
    user_profile = user_dir / f"{source}.yaml"
    if user_profile.is_file():
        return user_profile

    raise FileNotFoundError(
        f"Agent profile '{source}' not found. "
        f"Checked: {path}, {builtin}, {user_profile}. "
        f"Available built-in profiles: {', '.join(list_profiles()) or '(none)'}"
    )
