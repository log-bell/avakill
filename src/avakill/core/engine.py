"""Core Guard class -- the main entry point for AvaKill."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from avakill.core.exceptions import PolicyViolation, RateLimitExceeded
from avakill.core.integrity import PolicyIntegrity
from avakill.core.models import AuditEvent, Decision, PolicyConfig, ToolCall
from avakill.core.policy import PolicyEngine, load_policy
from avakill.core.self_protection import SelfProtection
from avakill.logging.base import AuditLogger
from avakill.logging.event_bus import EventBus

_logger = logging.getLogger(__name__)


class Guard:
    """The central AvaKill controller.

    Usage::

        guard = Guard(policy="avakill.yaml")
        decision = guard.evaluate(tool="delete_user", args={"user_id": "123"})
        if not decision.allowed:
            raise PolicyViolation(...)

    Or with context manager for automatic session tracking::

        with guard.session(agent_id="my-agent") as session:
            decision = session.evaluate(tool="search", args={...})
    """

    def __init__(
        self,
        policy: str | Path | dict | PolicyConfig | None = None,
        logger: AuditLogger | None = None,
        agent_id: str | None = None,
        self_protection: bool = True,
        signing_key: bytes | None = None,
    ) -> None:
        """Initialise the Guard.

        Args:
            policy: A filesystem path (str/Path) to a YAML policy file,
                a dict of raw config, a ``PolicyConfig`` object, or ``None``
                to auto-detect avakill.yaml in cwd.
            logger: An optional ``AuditLogger`` for recording events.
                If None, no audit logging is performed.
            agent_id: Default agent identifier for attribution.
            self_protection: Enable hardcoded self-protection rules that
                prevent agents from weakening their own guardrails.
                Set to False only for testing.
            signing_key: Optional 32-byte HMAC signing key for policy
                verification. If None, reads from AVAKILL_POLICY_KEY env var.

        Raises:
            ConfigError: If the policy cannot be loaded or parsed.
        """
        # Auto-read signing key from environment if not provided
        if signing_key is None:
            key_hex = os.environ.get("AVAKILL_POLICY_KEY")
            if key_hex:
                signing_key = bytes.fromhex(key_hex)

        self._integrity: PolicyIntegrity | None = None
        self._policy_path: Path | None = None

        if isinstance(policy, (str, Path)):
            self._policy_path = Path(policy)

        # Use PolicyIntegrity for file-based policies when signing is available
        if signing_key is not None and isinstance(policy, (str, Path)):
            self._integrity = PolicyIntegrity(signing_key=signing_key)
            config = self._integrity.load_verified(policy)
            self._engine = PolicyEngine(config)
            self._policy_status = (
                "verified" if self._integrity.get_last_known_good() is not None else "deny-all"
            )
        else:
            self._engine = self._build_engine(policy)
            self._policy_status = "unsigned"

        self._signing_key = signing_key
        self._logger = logger
        self._agent_id = agent_id
        self._self_protection: SelfProtection | None = (
            SelfProtection() if self_protection else None
        )
        self._event_bus = EventBus.get()

    @staticmethod
    def _build_engine(policy: str | Path | dict | PolicyConfig | None) -> PolicyEngine:
        """Construct a PolicyEngine from the various supported input types."""
        if isinstance(policy, PolicyConfig):
            return PolicyEngine(policy)
        if isinstance(policy, dict):
            return PolicyEngine.from_dict(policy)
        if isinstance(policy, (str, Path)):
            return PolicyEngine.from_yaml(policy)
        # None → auto-detect
        return load_policy()

    @property
    def engine(self) -> PolicyEngine:
        """The underlying PolicyEngine."""
        return self._engine

    @property
    def event_bus(self) -> EventBus:
        """The event bus used for broadcasting audit events."""
        return self._event_bus

    @property
    def policy_status(self) -> str:
        """Current integrity status: verified/last-known-good/deny-all/unsigned."""
        return self._policy_status

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate a tool call against the loaded policy.

        Args:
            tool: The name of the tool being invoked.
            args: Arguments passed to the tool.
            agent_id: Override agent identifier (falls back to Guard default).
            session_id: Optional session identifier.
            metadata: Arbitrary metadata attached to the call.

        Returns:
            A ``Decision`` indicating whether the call is allowed.
        """
        tool_call = ToolCall(
            tool_name=tool,
            arguments=args or {},
            agent_id=agent_id or self._agent_id,
            session_id=session_id,
            metadata=metadata or {},
        )

        start = time.monotonic()

        # Self-protection check runs before user-defined policy rules
        if self._self_protection is not None:
            sp_decision = self._self_protection.check(tool_call)
            if sp_decision is not None:
                elapsed_ms = (time.monotonic() - start) * 1000
                sp_decision = Decision(
                    allowed=sp_decision.allowed,
                    action=sp_decision.action,
                    policy_name=sp_decision.policy_name,
                    reason=sp_decision.reason,
                    latency_ms=elapsed_ms,
                )
                self._record(tool_call, sp_decision, start)
                return sp_decision

        # Integrity check: verify policy file hasn't been tampered with
        if self._integrity is not None and self._policy_path is not None:
            ok, msg = self._integrity.check_integrity(self._policy_path)
            if not ok:
                _logger.warning("Policy integrity check failed: %s", msg)
                fallback = self._integrity.load_verified(self._policy_path)
                self._engine = PolicyEngine(fallback)
                self._policy_status = (
                    "last-known-good"
                    if self._integrity.get_last_known_good() is not None
                    else "deny-all"
                )

        try:
            decision = self._engine.evaluate(tool_call)
        except RateLimitExceeded as exc:
            decision = exc.decision
            self._record(tool_call, decision, start)
            raise
        elapsed_ms = (time.monotonic() - start) * 1000

        # Re-stamp latency measured from this layer
        decision = Decision(
            allowed=decision.allowed,
            action=decision.action,
            policy_name=decision.policy_name,
            reason=decision.reason,
            latency_ms=elapsed_ms,
        )

        self._record(tool_call, decision, start)
        return decision

    def evaluate_or_raise(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Decision:
        """Evaluate a tool call, raising on denial.

        Same as :meth:`evaluate` but raises ``PolicyViolation`` when the
        decision is not allowed.

        Returns:
            The ``Decision`` (always allowed).

        Raises:
            PolicyViolation: If the tool call is denied by policy.
            RateLimitExceeded: If a rate limit is exceeded.
        """
        decision = self.evaluate(tool, args, **kwargs)
        if not decision.allowed:
            raise PolicyViolation(tool, decision)
        return decision

    def session(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> GuardSession:
        """Create a session context manager.

        Args:
            agent_id: Override agent identifier for this session.
            session_id: Explicit session id (auto-generated if None).

        Returns:
            A ``GuardSession`` context manager.
        """
        return GuardSession(
            guard=self,
            agent_id=agent_id or self._agent_id,
            session_id=session_id or str(uuid4()),
        )

    def reload_policy(self, path: str | Path | None = None) -> None:
        """Hot-reload the policy file without restarting.

        Args:
            path: Explicit path to reload from. If None, reloads from the
                originally-supplied path, or auto-detects.

        Raises:
            ConfigError: If the policy cannot be loaded or parsed.
        """
        reload_path: str | Path | None = path
        if reload_path is None:
            reload_path = self._policy_path

        if self._integrity is not None and reload_path is not None:
            config = self._integrity.load_verified(reload_path)
            self._engine = PolicyEngine(config)
            self._policy_status = (
                "verified"
                if self._integrity.get_last_known_good() is not None
                else "deny-all"
            )
        else:
            self._engine = self._build_engine(reload_path)

        if isinstance(reload_path, (str, Path)):
            self._policy_path = Path(reload_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record(
        self,
        tool_call: ToolCall,
        decision: Decision,
        _start: float,
    ) -> None:
        """Create an AuditEvent, log it asynchronously, and emit to bus."""
        event = AuditEvent(tool_call=tool_call, decision=decision)

        # Fire-and-forget async logging
        if self._logger is not None:
            self._log_async(event)

        # Synchronous event-bus emit
        self._event_bus.emit(event)

    def _log_async(self, event: AuditEvent) -> None:
        """Log an event without blocking the caller."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._logger.log(event))  # type: ignore[union-attr]
        except RuntimeError:
            # No running event loop — fire in a background thread
            t = threading.Thread(
                target=self._log_sync,
                args=(event,),
                daemon=True,
            )
            t.start()

    def _log_sync(self, event: AuditEvent) -> None:
        """Run the async logger.log in a new event loop (background thread)."""
        asyncio.run(self._logger.log(event))  # type: ignore[union-attr]


class GuardSession:
    """Wraps a Guard with fixed agent_id and session_id.

    Usage::

        with guard.session(agent_id="bot") as s:
            s.evaluate(tool="search", args={"q": "hello"})
            print(s.call_count)  # 1
    """

    def __init__(
        self,
        guard: Guard,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self._guard = guard
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid4())
        self.call_count = 0

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Decision:
        """Evaluate a tool call within this session."""
        self.call_count += 1
        return self._guard.evaluate(
            tool,
            args,
            agent_id=self.agent_id,
            session_id=self.session_id,
            **kwargs,
        )

    def evaluate_or_raise(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Decision:
        """Evaluate a tool call, raising on denial."""
        self.call_count += 1
        return self._guard.evaluate_or_raise(
            tool,
            args,
            agent_id=self.agent_id,
            session_id=self.session_id,
            **kwargs,
        )

    def __enter__(self) -> GuardSession:
        return self

    def __exit__(self, *_: Any) -> None:
        pass
