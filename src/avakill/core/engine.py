"""Core Guard class -- the main entry point for AvaKill."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from avakill._telemetry import record_duration as otel_record_duration
from avakill._telemetry import record_evaluation as otel_record_evaluation
from avakill._telemetry import (
    record_self_protection_block as otel_record_sp_block,
)
from avakill._telemetry import record_violation as otel_record_violation
from avakill.core.exceptions import PolicyViolation, RateLimitExceeded
from avakill.core.integrity import PolicyIntegrity
from avakill.core.models import AuditEvent, Decision, PolicyConfig, ToolCall
from avakill.core.normalization import normalize_tool_name
from avakill.core.policy import PolicyEngine, load_policy
from avakill.core.rate_limit_store import RateLimitBackend
from avakill.core.recovery import recovery_hint_for
from avakill.core.self_protection import SelfProtection
from avakill.logging.base import AuditLogger
from avakill.logging.event_bus import EventBus
from avakill.metrics import inc_evaluations as prom_inc_evaluations
from avakill.metrics import inc_self_protection_blocks as prom_inc_sp_blocks
from avakill.metrics import inc_violations as prom_inc_violations
from avakill.metrics import observe_duration as prom_observe_duration

if TYPE_CHECKING:
    from avakill.core.approval import ApprovalStore
    from avakill.core.watcher import PolicyWatcher

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
        verify_key: bytes | None = None,
        rate_limit_backend: RateLimitBackend | None = None,
        normalize_tools: bool = False,
        approval_store: ApprovalStore | None = None,
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
            verify_key: Optional 32-byte Ed25519 public key for policy
                verification. If None, reads from AVAKILL_VERIFY_KEY env var.
            rate_limit_backend: Optional persistent backend for rate-limit
                timestamps. When ``None``, rate limits are in-memory only.

        Raises:
            ConfigError: If the policy cannot be loaded or parsed.
        """
        # Auto-read signing key from environment if not provided
        if signing_key is None:
            key_hex = os.environ.get("AVAKILL_POLICY_KEY")
            if key_hex:
                signing_key = bytes.fromhex(key_hex)

        # Auto-read Ed25519 verify key from environment if not provided
        if verify_key is None:
            vk_hex = os.environ.get("AVAKILL_VERIFY_KEY")
            if vk_hex:
                verify_key = bytes.fromhex(vk_hex)

        self._integrity: PolicyIntegrity | None = None
        self._policy_path: Path | None = None
        self._rate_limit_backend = rate_limit_backend

        if isinstance(policy, str | Path):
            self._policy_path = Path(policy)

        # Use PolicyIntegrity for file-based policies when signing is available
        has_signing = signing_key is not None or verify_key is not None
        if has_signing and isinstance(policy, str | Path):
            self._integrity = PolicyIntegrity(signing_key=signing_key, verify_key=verify_key)
            config = self._integrity.load_verified(policy)
            self._engine = PolicyEngine(config, rate_limit_backend=rate_limit_backend)
            self._policy_status = (
                "verified" if self._integrity.get_last_known_good() is not None else "deny-all"
            )
        else:
            self._engine = self._build_engine(policy, rate_limit_backend)
            self._policy_status = "unsigned"

        self._signing_key = signing_key
        self._verify_key = verify_key
        self._logger = logger
        self._agent_id = agent_id
        self._self_protection: SelfProtection | None = SelfProtection() if self_protection else None
        self._normalize_tools = normalize_tools
        self._approval_store = approval_store
        self._event_bus = EventBus.get()
        self._log_failures = 0
        self._watcher: PolicyWatcher | None = None

    @staticmethod
    def _build_engine(
        policy: str | Path | dict | PolicyConfig | None,
        rate_limit_backend: RateLimitBackend | None = None,
    ) -> PolicyEngine:
        """Construct a PolicyEngine from the various supported input types."""
        if isinstance(policy, PolicyConfig):
            return PolicyEngine(policy, rate_limit_backend=rate_limit_backend)
        if isinstance(policy, dict):
            engine = PolicyEngine.from_dict(policy)
            if rate_limit_backend is not None:
                engine._backend = rate_limit_backend
                engine._persistent = True
                engine._hydrate()
            return engine
        if isinstance(policy, str | Path):
            engine = PolicyEngine.from_yaml(policy)
            if rate_limit_backend is not None:
                engine._backend = rate_limit_backend
                engine._persistent = True
                engine._hydrate()
            return engine
        # None -> auto-detect
        engine = load_policy()
        if rate_limit_backend is not None:
            engine._backend = rate_limit_backend
            engine._persistent = True
            engine._hydrate()
        return engine

    @property
    def engine(self) -> PolicyEngine:
        """The underlying PolicyEngine."""
        return self._engine

    @property
    def log_failures(self) -> int:
        """Number of audit-logging failures since Guard creation."""
        return self._log_failures

    @property
    def event_bus(self) -> EventBus:
        """The event bus used for broadcasting audit events."""
        return self._event_bus

    @property
    def policy_status(self) -> str:
        """Current integrity status: hardened/verified/last-known-good/deny-all/unsigned."""
        if self._policy_status == "verified":
            from avakill.core.audit_hooks import c_hooks_available

            if c_hooks_available():
                return "hardened"
        return self._policy_status

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        override: bool = False,
    ) -> Decision:
        """Evaluate a tool call against the loaded policy.

        Args:
            tool: The name of the tool being invoked.
            args: Arguments passed to the tool.
            agent_id: Override agent identifier (falls back to Guard default).
            session_id: Optional session identifier.
            metadata: Arbitrary metadata attached to the call.
            override: When ``True`` and the decision is overridable (soft
                enforcement), flip the deny to an allow with an ``[override]``
                audit trail.

        Returns:
            A ``Decision`` indicating whether the call is allowed.
        """
        effective_agent = agent_id or self._agent_id
        tool_call = ToolCall(
            tool_name=tool,
            arguments=args or {},
            agent_id=effective_agent,
            session_id=session_id,
            metadata=metadata or {},
        )

        # Normalize agent-specific tool names to canonical form
        if self._normalize_tools and effective_agent:
            canonical = normalize_tool_name(tool, effective_agent)
            if canonical != tool:
                tool_call = ToolCall(
                    tool_name=canonical,
                    arguments=tool_call.arguments,
                    agent_id=tool_call.agent_id,
                    session_id=tool_call.session_id,
                    metadata=tool_call.metadata,
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
            if exc.recovery_hint is None:
                exc.recovery_hint = recovery_hint_for(
                    exc.decision,
                    policy_status=self._policy_status,
                    tool_name=tool_call.tool_name,
                )
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
            overridable=decision.overridable,
        )

        # Override: flip overridable denies to allow when requested
        if override and decision.overridable and not decision.allowed:
            decision = Decision(
                allowed=True,
                action="allow",
                policy_name=decision.policy_name,
                reason=f"[override] {decision.reason}",
                latency_ms=elapsed_ms,
            )

        # Approval workflow: check for pre-approved requests or create pending
        if decision.action == "require_approval" and self._approval_store is not None:
            decision = self._check_approval(tool_call, decision, elapsed_ms)

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
            hint = recovery_hint_for(
                decision,
                policy_status=self._policy_status,
                tool_name=tool,
            )
            raise PolicyViolation(tool, decision, recovery_hint=hint)
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
            self._engine = PolicyEngine(config, rate_limit_backend=self._rate_limit_backend)
            self._policy_status = (
                "verified" if self._integrity.get_last_known_good() is not None else "deny-all"
            )
        else:
            self._engine = self._build_engine(reload_path, self._rate_limit_backend)

        if isinstance(reload_path, str | Path):
            self._policy_path = Path(reload_path)

    def watch(self, **kwargs: Any) -> PolicyWatcher:
        """Create a :class:`PolicyWatcher` for this guard.

        The watcher is stored internally and must be started separately
        via ``await watcher.start()`` or used as an async context manager.

        Args:
            **kwargs: Forwarded to :class:`PolicyWatcher.__init__`.

        Returns:
            The created :class:`PolicyWatcher`.

        Raises:
            RuntimeError: If a watcher is already active.
            ValueError: If the guard has no file-based policy.
        """
        if self._watcher is not None:
            raise RuntimeError("A PolicyWatcher is already active; call unwatch() first")
        from avakill.core.watcher import PolicyWatcher as _PW

        self._watcher = _PW(self, **kwargs)
        return self._watcher

    async def unwatch(self) -> None:
        """Stop and remove the active :class:`PolicyWatcher`."""
        if self._watcher is not None:
            await self._watcher.stop()
            self._watcher = None

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
        hint = None
        if not decision.allowed:
            hint = recovery_hint_for(
                decision,
                policy_status=self._policy_status,
                tool_name=tool_call.tool_name,
            )
        event = AuditEvent(tool_call=tool_call, decision=decision, recovery_hint=hint)

        # Fire-and-forget async logging
        if self._logger is not None:
            self._log_async(event)

        # Synchronous event-bus emit
        self._event_bus.emit(event)

        elapsed_ms = (time.monotonic() - _start) * 1000

        # OTel telemetry (fault-isolated)
        with contextlib.suppress(Exception):
            otel_record_evaluation(
                tool=tool_call.tool_name,
                action=decision.action,
                agent_id=tool_call.agent_id,
            )
            otel_record_duration(tool=tool_call.tool_name, duration_ms=elapsed_ms)
            if not decision.allowed:
                otel_record_violation(
                    tool=tool_call.tool_name,
                    policy=decision.policy_name or "",
                    reason=decision.reason,
                )
            if decision.policy_name == "self-protection":
                otel_record_sp_block(tool=tool_call.tool_name)

        # Prometheus metrics (fault-isolated)
        with contextlib.suppress(Exception):
            prom_inc_evaluations(
                tool=tool_call.tool_name,
                action=decision.action,
                agent_id=tool_call.agent_id,
            )
            prom_observe_duration(
                tool=tool_call.tool_name,
                duration_seconds=elapsed_ms / 1000,
            )
            if not decision.allowed:
                prom_inc_violations(
                    tool=tool_call.tool_name,
                    policy=decision.policy_name or "",
                )
            if decision.policy_name == "self-protection":
                prom_inc_sp_blocks(tool=tool_call.tool_name)

    def _check_approval(
        self, tool_call: ToolCall, decision: Decision, elapsed_ms: float
    ) -> Decision:
        """Check the approval store for a pre-approved request or create a pending one.

        Runs the async approval check in a thread-pool when called from
        inside a running event loop, ensuring the result is always
        returned synchronously to the caller.
        """
        assert self._approval_store is not None

        try:
            asyncio.get_running_loop()
            # We're in an async context — run in a new thread with its own
            # event loop so we can return the result synchronously without
            # blocking the caller's loop.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self._check_approval_sync, tool_call, decision, elapsed_ms)
                return future.result(timeout=5.0)
        except RuntimeError:
            # No running event loop — run synchronously
            return self._check_approval_sync(tool_call, decision, elapsed_ms)

    async def _check_approval_async(
        self, tool_call: ToolCall, decision: Decision, elapsed_ms: float
    ) -> Decision:
        """Async approval check: look for approved request or create pending."""
        assert self._approval_store is not None
        store = self._approval_store
        agent = tool_call.agent_id or ""

        # Check for an existing approved request for this tool+agent
        approved = await store.get_approved_for_tool(tool_call.tool_name, agent)
        if approved is not None:
            return Decision(
                allowed=True,
                action="allow",
                policy_name=decision.policy_name,
                reason=f"[approved] {decision.reason}",
                latency_ms=elapsed_ms,
            )

        # No pre-approval found — create a pending request
        await store.create(tool_call, decision, agent=agent)
        return decision

    def _check_approval_sync(
        self, tool_call: ToolCall, decision: Decision, elapsed_ms: float
    ) -> Decision:
        """Synchronous approval check (new event loop in current thread)."""
        return asyncio.run(self._check_approval_async(tool_call, decision, elapsed_ms))

    def _log_async(self, event: AuditEvent) -> None:
        """Log an event without blocking the caller."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._logger.log(event))  # type: ignore[union-attr]
            task.add_done_callback(self._on_log_done)
        except RuntimeError:
            # No running event loop — buffer the event directly so it's
            # available when the caller next invokes flush().  This avoids
            # spawning a daemon thread whose event loop creates a separate
            # DB connection that won't be visible to subsequent flush/query
            # calls in the caller's own asyncio.run().
            try:
                self._logger._buffer.append(event)  # type: ignore[union-attr]
            except Exception as exc:
                self._log_failures += 1
                _logger.error("Audit logging failed (sync): %s", exc)

    def _on_log_done(self, task: asyncio.Task[None]) -> None:
        """Callback for completed async log tasks."""
        exc = task.exception()
        if exc is not None:
            self._log_failures += 1
            _logger.error("Audit logging failed: %s", exc)


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
