"""Multi-level policy cascade.

Discovers and merges policy files from multiple levels:

1. **system** — ``/etc/avakill/policy.yaml`` (admin-managed)
2. **global** — ``~/.config/avakill/policy.yaml`` (user-wide)
3. **project** — ``.avakill/policy.yaml`` or ``avakill.yaml`` (in cwd or parents)
4. **local** — ``.avakill/policy.local.yaml`` (gitignored overrides)

Merge semantics are *deny-wins*: a deny rule at any level cannot be
overridden by a lower level, and the most restrictive rate limit wins.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

import yaml
from pydantic import ValidationError

from avakill.core.exceptions import ConfigError
from avakill.core.models import PolicyConfig, PolicyRule

PolicyLevel = Literal["system", "global", "project", "local"]

SYSTEM_POLICY_PATH = Path("/etc/avakill/policy.yaml")
GLOBAL_POLICY_PATH = Path.home() / ".config" / "avakill" / "policy.yaml"

# Project-level filenames searched in cwd and parent directories
_PROJECT_FILENAMES = (
    ".avakill/policy.yaml",
    "avakill.yaml",
    "avakill.yml",
)

# Local override (gitignored)
_LOCAL_FILENAME = ".avakill/policy.local.yaml"


class PolicyCascade:
    """Discover, load, and merge policy files from multiple levels."""

    def discover(self, cwd: Path | None = None) -> list[tuple[PolicyLevel, Path]]:
        """Find all policy files in the cascade.

        Args:
            cwd: Working directory for project/local discovery.
                Defaults to ``Path.cwd()``.

        Returns:
            List of ``(level_name, path)`` pairs in cascade order
            (system first, local last).
        """
        found: list[tuple[PolicyLevel, Path]] = []

        if SYSTEM_POLICY_PATH.is_file():
            found.append(("system", SYSTEM_POLICY_PATH))

        if GLOBAL_POLICY_PATH.is_file():
            found.append(("global", GLOBAL_POLICY_PATH))

        search_dir = Path(cwd) if cwd else Path.cwd()
        project_path = self._find_project_policy(search_dir)
        if project_path is not None:
            found.append(("project", project_path))

        local_path = self._find_local_policy(search_dir)
        if local_path is not None:
            found.append(("local", local_path))

        return found

    def load(self, cwd: Path | None = None) -> PolicyConfig:
        """Load and merge all discovered policy files.

        Args:
            cwd: Working directory for project/local discovery.

        Returns:
            A merged :class:`PolicyConfig`.

        Raises:
            ConfigError: If no policy files are found.
        """
        discovered = self.discover(cwd)
        if not discovered:
            raise ConfigError(
                "No policy files found in cascade "
                "(checked system, global, project, local levels)."
            )

        configs: list[PolicyConfig] = []
        for _level, path in discovered:
            try:
                raw = path.read_text(encoding="utf-8")
                data = yaml.safe_load(raw)
                if data is None:
                    data = {}
                if not isinstance(data, dict):
                    raise ConfigError(
                        f"Policy file {path} must be a YAML mapping at the top level"
                    )
                config = PolicyConfig.model_validate(data)
                configs.append(config)
            except yaml.YAMLError as exc:
                raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
            except ValidationError as exc:
                raise ConfigError(
                    f"Invalid policy in {path}: {exc}"
                ) from exc

        return self.merge(configs)

    @staticmethod
    def merge(configs: list[PolicyConfig]) -> PolicyConfig:
        """Merge multiple policy configs with deny-wins semantics.

        Rules:
        - ``default_action``: ``"deny"`` if any level says ``"deny"``
        - Deny rules: union (accumulated from all levels)
        - Allow rules: kept only if no higher level denies the same tools
        - Rate limits: most restrictive (lowest ``max_calls``) wins
        - Hard enforcement cannot be relaxed by lower levels

        Args:
            configs: Ordered list of configs (highest priority first).

        Returns:
            A new merged :class:`PolicyConfig`.
        """
        if not configs:
            return PolicyConfig(
                version="1.0", default_action="deny", policies=[]
            )

        if len(configs) == 1:
            return configs[0].model_copy(deep=True)

        # Determine default action: deny if any level says deny
        default_action: Literal["allow", "deny"] = "allow"
        for cfg in configs:
            if cfg.default_action == "deny":
                default_action = "deny"
                break

        # Collect all deny tool patterns from higher levels
        # so we can prevent lower levels from allowing them
        hard_denied_patterns: set[str] = set()
        merged_rules: list[PolicyRule] = []
        seen_rule_names: set[str] = set()

        for cfg in configs:
            for rule in cfg.policies:
                # Deduplicate by name: first occurrence wins
                if rule.name in seen_rule_names:
                    continue
                seen_rule_names.add(rule.name)

                if rule.action == "deny":
                    merged_rules.append(rule.model_copy(deep=True))
                    if rule.enforcement == "hard":
                        hard_denied_patterns.update(rule.tools)
                elif rule.action == "allow":
                    # Only keep allow if it doesn't conflict with a
                    # hard deny from a higher level.  Use fnmatch in
                    # both directions so that deny "file_*" blocks
                    # allow "file_write" and deny "file_write" blocks
                    # allow "file_*".
                    dominated = any(
                        fnmatch(tool, deny_pat) or fnmatch(deny_pat, tool)
                        for tool in rule.tools
                        for deny_pat in hard_denied_patterns
                    )
                    if not dominated:
                        merged_rules.append(rule.model_copy(deep=True))
                else:
                    # require_approval: keep as-is
                    merged_rules.append(rule.model_copy(deep=True))

        # Merge rate limits: for rules matching the same tool patterns,
        # keep the most restrictive limit
        merged_rules = _merge_rate_limits(merged_rules)

        return PolicyConfig(
            version="1.0",
            default_action=default_action,
            policies=merged_rules,
        )

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_project_policy(search_dir: Path) -> Path | None:
        """Walk up from *search_dir* looking for a project-level policy."""
        current = search_dir.resolve()
        for _ in range(50):  # safety limit
            for name in _PROJECT_FILENAMES:
                candidate = current / name
                if candidate.is_file():
                    return candidate
            parent = current.parent
            if parent == current:
                break
            current = parent
        return None

    @staticmethod
    def _find_local_policy(search_dir: Path) -> Path | None:
        """Look for a local override policy in *search_dir*."""
        candidate = search_dir / _LOCAL_FILENAME
        return candidate if candidate.is_file() else None


def _merge_rate_limits(rules: list[PolicyRule]) -> list[PolicyRule]:
    """For rules with the same tool set, keep the most restrictive rate limit."""
    # Track the most restrictive rate-limited rule per tool set
    best_rate: dict[frozenset[str], PolicyRule] = {}
    result: list[PolicyRule] = []

    for rule in rules:
        key = frozenset(rule.tools)
        if rule.rate_limit is not None and key in best_rate:
            existing = best_rate[key]
            if rule.rate_limit.max_calls < existing.rate_limit.max_calls:
                # Replace the existing entry in result with the more restrictive one
                idx = result.index(existing)
                result[idx] = rule.model_copy(deep=True)
                best_rate[key] = result[idx]
            # Otherwise skip the less restrictive duplicate
        else:
            result.append(rule)
            if rule.rate_limit is not None:
                best_rate[key] = rule

    return result
