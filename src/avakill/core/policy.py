"""Policy engine for parsing YAML configs and evaluating tool calls against rules."""

from __future__ import annotations

import os
import re
import threading
import time
from collections import defaultdict, deque
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from avakill.core.exceptions import ConfigError, RateLimitExceeded
from avakill.core.models import (
    Decision,
    PolicyConfig,
    RateLimit,
    RuleConditions,
    ToolCall,
)
from avakill.core.rate_limit_store import InMemoryBackend, RateLimitBackend

_ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)\}")


class PolicyEngine:
    """Parses YAML policy files and evaluates tool calls against rules.

    Evaluation logic:
    1. Iterate through policies in order (first match wins)
    2. For each rule, check if the tool_name matches any pattern in rule.tools
       - Support exact match: "database_query"
       - Support glob patterns: "database_*", "*_execute"
       - Support "all" or "*" to match everything
    3. If tool matches, check conditions (if any):
       - args_match: For each key in args_match, check if the corresponding
         argument value (converted to string) contains any of the specified
         substrings (case-insensitive). ALL keys must match (AND logic).
       - args_not_match: Same as args_match but inverted — if ANY match,
         the condition FAILS (deny)
    4. If conditions pass, check rate limit (if any):
       - Track call counts per (tool_name) in a sliding window
       - If exceeded, deny with RateLimitExceeded
    5. Return the rule's action as the Decision
    6. If no rule matches, use default_action
    """

    def __init__(
        self,
        config: PolicyConfig,
        rate_limit_backend: RateLimitBackend | None = None,
    ) -> None:
        """Initialise the engine with a parsed policy config.

        Args:
            config: The validated policy configuration.
            rate_limit_backend: Optional persistent backend for rate-limit
                timestamps.  When ``None`` (the default), an
                :class:`InMemoryBackend` is used and counters reset on
                restart.
        """
        self._config = config
        self._rate_limit_windows: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._backend: RateLimitBackend = rate_limit_backend or InMemoryBackend()
        self._persistent = not isinstance(self._backend, InMemoryBackend)

        # Hydrate in-memory deques from the persistent backend
        if self._persistent:
            self._hydrate()

    @property
    def config(self) -> PolicyConfig:
        """The underlying policy configuration."""
        return self._config

    def _hydrate(self) -> None:
        """Load unexpired timestamps from the persistent backend into memory.

        Uses the maximum configured window across all rules so that no
        unexpired data is discarded.  Also cleans up rows that have
        expired beyond the max window.
        """
        max_window = max(
            (r.rate_limit.window_seconds() for r in self._config.policies if r.rate_limit),
            default=0,
        )
        if max_window == 0:
            return

        # Prune stale rows, then load everything still within the max window
        self._backend.cleanup(max_window)
        all_timestamps = self._backend.load_all(max_window)
        for tool_name, timestamps in all_timestamps.items():
            self._rate_limit_windows[tool_name] = deque(timestamps)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Create a PolicyEngine by parsing a YAML policy file.

        Environment variables in the form ``${VAR_NAME}`` are substituted
        from ``os.environ`` before parsing.

        Args:
            path: Filesystem path to a YAML policy file.

        Returns:
            A new PolicyEngine instance.

        Raises:
            ConfigError: If the file is missing or the YAML is invalid.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise ConfigError(f"Policy file not found: {filepath}")
        try:
            raw = filepath.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"Failed to read policy file: {exc}") from exc
        return cls.from_string(raw)

    @classmethod
    def from_string(cls, yaml_string: str) -> PolicyEngine:
        """Create a PolicyEngine from a YAML string.

        Environment variables in the form ``${VAR_NAME}`` are substituted
        from ``os.environ`` before parsing.

        Args:
            yaml_string: A YAML-formatted policy string.

        Returns:
            A new PolicyEngine instance.

        Raises:
            ConfigError: If the string cannot be parsed as a valid policy.
        """
        substituted = _ENV_VAR_PATTERN.sub(
            lambda m: os.environ.get(m.group(1), m.group(0)),
            yaml_string,
        )
        try:
            data = yaml.safe_load(substituted)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML: {exc}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError("Policy YAML must be a mapping at the top level")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        """Create a PolicyEngine from a raw dictionary.

        Args:
            data: Dictionary matching the ``PolicyConfig`` schema.

        Returns:
            A new PolicyEngine instance.

        Raises:
            ConfigError: If the dictionary cannot be parsed as a valid policy.
        """
        try:
            config = PolicyConfig.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(f"Invalid policy configuration: {exc}") from exc
        return cls(config)

    def evaluate(self, tool_call: ToolCall) -> Decision:
        """Evaluate a tool call against the loaded policy rules.

        Rules are checked in order; the first matching rule determines the
        decision.  If no rule matches, ``PolicyConfig.default_action`` is used.

        Args:
            tool_call: The tool call to evaluate.

        Returns:
            A ``Decision`` indicating whether the call is allowed.

        Raises:
            RateLimitExceeded: If a matching rule's rate limit is exceeded.
        """
        start = time.monotonic()

        for rule in self._config.policies:
            if not self._match_tool(tool_call.tool_name, rule.tools):
                continue

            if rule.conditions and not self._check_conditions(tool_call, rule.conditions):
                continue

            # Rule matches — check rate limit before returning decision
            if rule.rate_limit and not self._check_rate_limit(tool_call, rule.rate_limit):
                elapsed = (time.monotonic() - start) * 1000
                decision = Decision(
                    allowed=False,
                    action="deny",
                    policy_name=rule.name,
                    reason=(
                        f"Rate limit exceeded: {rule.rate_limit.max_calls} calls "
                        f"per {rule.rate_limit.window}"
                    ),
                    latency_ms=elapsed,
                )
                raise RateLimitExceeded(tool_call.tool_name, decision)

            elapsed = (time.monotonic() - start) * 1000

            # Advisory enforcement: log the match but always allow
            if rule.enforcement == "advisory" and rule.action == "deny":
                return Decision(
                    allowed=True,
                    action="allow",
                    policy_name=rule.name,
                    reason=f"[advisory] {rule.message or f'Matched rule {rule.name!r}'}",
                    latency_ms=elapsed,
                )

            allowed = rule.action == "allow"
            reason = rule.message or f"Matched rule '{rule.name}'"
            overridable = False

            # Soft enforcement: deny still blocks by default, but flag as overridable
            if rule.enforcement == "soft" and not allowed:
                reason = f"[overridable] {reason}"
                overridable = True

            return Decision(
                allowed=allowed,
                action=rule.action,
                policy_name=rule.name,
                reason=reason,
                latency_ms=elapsed,
                overridable=overridable,
            )

        # No rule matched — use default action
        elapsed = (time.monotonic() - start) * 1000
        action = self._config.default_action
        allowed = action == "allow"
        return Decision(
            allowed=allowed,
            action=action,
            reason=f"No matching rule; default action is '{action}'",
            latency_ms=elapsed,
        )

    def _match_tool(self, tool_name: str, patterns: list[str]) -> bool:
        """Check if a tool name matches any of the given patterns.

        Supports exact match, fnmatch glob patterns, and the special
        value ``"all"`` which matches everything.

        Args:
            tool_name: The tool name to check.
            patterns: List of patterns (exact names or globs).

        Returns:
            True if any pattern matches the tool name.
        """
        for pattern in patterns:
            if pattern in ("*", "all"):
                return True
            if fnmatch(tool_name, pattern):
                return True
        return False

    def _check_conditions(self, tool_call: ToolCall, conditions: RuleConditions) -> bool:
        """Evaluate rule conditions against a tool call's arguments.

        - ``args_match``: ALL keys must match (AND). For each key the
          argument value (as a string, case-insensitive) must contain at
          least one of the specified substrings.
        - ``args_not_match``: If ANY key's argument value contains any
          of the specified substrings, the condition fails.

        Args:
            tool_call: The tool call to check.
            conditions: The conditions to evaluate.

        Returns:
            True if all conditions are satisfied.
        """
        args = tool_call.arguments

        if conditions.shell_safe:
            cmd = str(args.get("command") or args.get("cmd") or "")
            if cmd:
                from avakill.core.shell_analysis import is_shell_safe

                safe, _ = is_shell_safe(cmd)
                if not safe:
                    return False

        if conditions.command_allowlist:
            cmd = str(args.get("command") or args.get("cmd") or "")
            parts = cmd.split()
            first_token = parts[0].lower() if parts else ""
            if first_token not in {c.lower() for c in conditions.command_allowlist}:
                return False

        if conditions.args_match:
            for key, substrings in conditions.args_match.items():
                value = str(args.get(key, "")).lower()
                if not any(s.lower() in value for s in substrings):
                    return False

        if conditions.args_not_match:
            for key, substrings in conditions.args_not_match.items():
                value = str(args.get(key, "")).lower()
                if any(s.lower() in value for s in substrings):
                    return False

        if conditions.path_match and not self._check_path_match(
            args, conditions.path_match, conditions.workspace
        ):
            return False

        if conditions.path_not_match and self._check_path_match(
            args, conditions.path_not_match, conditions.workspace
        ):
            return False

        return not (
            conditions.content_scan and not self._check_content_scan(args, conditions.content_scan)
        )

    def _check_path_match(
        self,
        args: dict[str, Any],
        path_patterns: dict[str, list[str]],
        workspace: str | None = None,
    ) -> bool:
        """Check whether resolved argument paths fall under protected path prefixes.

        For each key in *path_patterns*, the argument value is resolved to
        absolute path(s).  If the key is ``command`` or ``cmd``, paths are
        extracted from the shell command first.  The ``__workspace__`` sentinel
        in pattern strings is replaced with the resolved workspace root.

        Args:
            args: The tool call arguments dict.
            path_patterns: Mapping of argument key → list of protected path
                prefixes.
            workspace: Optional explicit workspace root (overrides auto-detect).

        Returns:
            True if **all** keys have at least one resolved path matching a
            protected prefix (AND logic across keys).
        """
        from avakill.core.path_resolution import (
            detect_workspace_root,
            path_matches_protected,
            resolve_path,
            resolve_paths_from_value,
        )

        ws = workspace or detect_workspace_root()
        ws_resolved = resolve_path(ws)

        for key, patterns in path_patterns.items():
            value = str(args.get(key, ""))
            if not value:
                return False

            # Determine if this key is a command argument
            is_command = key.lower() in ("command", "cmd")

            # Resolve paths from the argument value
            resolved_paths = resolve_paths_from_value(value, is_command=is_command)
            if not resolved_paths:
                return False

            # Resolve protected path patterns (expand ~, $HOME, __workspace__)
            resolved_patterns = []
            for p in patterns:
                expanded = p.replace("__workspace__", ws_resolved)
                resolved_patterns.append(resolve_path(expanded))

            # Check if any resolved path matches a protected prefix
            if not any(path_matches_protected(rp, resolved_patterns) for rp in resolved_paths):
                return False

        return True

    def _check_content_scan(
        self,
        args: dict[str, Any],
        scan_types: list[str],
    ) -> bool:
        """Scan all string argument values for secrets or prompt injection.

        Args:
            args: The tool call arguments dict.
            scan_types: Scanner types to run (e.g. ``["secrets"]``).

        Returns:
            True if any scanner finds a match in any argument value.
        """
        from avakill.core.content_scanner import scan_content

        for value in args.values():
            text = str(value) if not isinstance(value, str) else value
            if not text:
                continue
            if scan_content(text, scan_types):
                return True
        return False

    def _check_rate_limit(self, tool_call: ToolCall, rate_limit: RateLimit) -> bool:
        """Check whether a tool call is within the configured rate limit.

        Uses a sliding-window approach with an in-memory deque of
        timestamps, protected by a thread lock.  When a persistent
        backend is configured, wall-clock time (``time.time()``) is used
        so that timestamps survive process restarts.

        Rate-limit counters are scoped per agent when ``tool_call.agent_id``
        is set, so that one agent exhausting its quota does not block another.

        Args:
            tool_call: The tool call to check.
            rate_limit: The rate limit configuration.

        Returns:
            True if the call is within the limit, False if exceeded.
        """
        # Build agent-scoped key when agent_id is present
        key = (
            f"{tool_call.agent_id}:{tool_call.tool_name}"
            if tool_call.agent_id
            else tool_call.tool_name
        )
        window_secs = rate_limit.window_seconds()
        now = time.time() if self._persistent else time.monotonic()

        with self._lock:
            timestamps = self._rate_limit_windows[key]

            # Purge expired entries
            while timestamps and (now - timestamps[0]) > window_secs:
                timestamps.popleft()

            if len(timestamps) >= rate_limit.max_calls:
                return False

            timestamps.append(now)

        # Persist outside the lock to keep the critical section short
        if self._persistent:
            self._backend.record(key, now)

        return True


def load_policy(path: str | Path | None = None) -> PolicyEngine:
    """Load a policy from a file path or auto-detect in the current directory.

    If no path is given, looks for ``avakill.yaml`` or
    ``avakill.yml`` in the current working directory.

    Args:
        path: Optional explicit path to a policy file.

    Returns:
        A PolicyEngine loaded from the file.

    Raises:
        ConfigError: If no policy file is found or the file is invalid.
    """
    if path is not None:
        return PolicyEngine.from_yaml(path)

    for name in ("avakill.yaml", "avakill.yml"):
        candidate = Path.cwd() / name
        if candidate.exists():
            return PolicyEngine.from_yaml(candidate)

    raise ConfigError("No policy file found. Create an avakill.yaml or pass an explicit path.")
