"""Tests for rate-limit persistence backends and PolicyEngine integration."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from avakill.core.exceptions import RateLimitExceeded
from avakill.core.models import PolicyConfig, PolicyRule, RateLimit, ToolCall
from avakill.core.policy import PolicyEngine
from avakill.core.rate_limit_store import InMemoryBackend, SQLiteBackend

# ---------------------------------------------------------------------------
# InMemoryBackend
# ---------------------------------------------------------------------------


class TestInMemoryBackend:
    """InMemoryBackend should be a no-op passthrough."""

    def test_load_returns_empty(self) -> None:
        backend = InMemoryBackend()
        assert backend.load("any_tool", 60.0) == []

    def test_load_all_returns_empty(self) -> None:
        backend = InMemoryBackend()
        assert backend.load_all(60.0) == {}

    def test_record_and_cleanup_are_noop(self) -> None:
        backend = InMemoryBackend()
        backend.record("tool", 1.0)
        backend.cleanup(60.0)
        backend.close()
        # No exceptions, no data stored


# ---------------------------------------------------------------------------
# SQLiteBackend
# ---------------------------------------------------------------------------


class TestSQLiteBackend:
    """Tests for the SQLite persistent backend."""

    def test_record_and_load(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("web_search", now - 10)
        backend.record("web_search", now - 5)
        backend.record("web_search", now)

        results = backend.load("web_search", 60.0)
        assert len(results) == 3
        backend.close()

    def test_load_filters_by_window(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("api_call", now - 120)  # outside 60s window
        backend.record("api_call", now - 30)  # inside
        backend.record("api_call", now)  # inside

        results = backend.load("api_call", 60.0)
        assert len(results) == 2
        backend.close()

    def test_load_filters_by_tool_name(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("tool_a", now)
        backend.record("tool_b", now)

        assert len(backend.load("tool_a", 60.0)) == 1
        assert len(backend.load("tool_b", 60.0)) == 1
        assert len(backend.load("tool_c", 60.0)) == 0
        backend.close()

    def test_load_all_groups_by_tool(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("tool_a", now - 10)
        backend.record("tool_a", now)
        backend.record("tool_b", now)

        result = backend.load_all(60.0)
        assert len(result["tool_a"]) == 2
        assert len(result["tool_b"]) == 1
        assert "tool_c" not in result
        backend.close()

    def test_load_all_filters_by_window(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("tool", now - 120)  # outside
        backend.record("tool", now)  # inside

        result = backend.load_all(60.0)
        assert len(result["tool"]) == 1
        backend.close()

    def test_cleanup_removes_old_entries(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()
        backend.record("tool", now - 200)
        backend.record("tool", now - 100)
        backend.record("tool", now)

        backend.cleanup(50.0)

        # Only the most recent entry should remain
        results = backend.load("tool", 300.0)
        assert len(results) == 1
        backend.close()

    def test_persistence_across_close_and_reopen(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        now = time.time()

        backend1 = SQLiteBackend(db)
        backend1.record("tool", now - 10)
        backend1.record("tool", now)
        backend1.close()

        backend2 = SQLiteBackend(db)
        results = backend2.load("tool", 60.0)
        assert len(results) == 2
        backend2.close()

    def test_batched_writes_flush_on_load(self, tmp_path: Path) -> None:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        now = time.time()

        # Write fewer than batch size - should still be visible on load
        for i in range(5):
            backend.record("tool", now - i)

        results = backend.load("tool", 60.0)
        assert len(results) == 5
        backend.close()


# ---------------------------------------------------------------------------
# PolicyEngine + SQLiteBackend integration
# ---------------------------------------------------------------------------


class TestPolicyEngineSQLiteIntegration:
    """Test that PolicyEngine works correctly with SQLiteBackend."""

    def _make_engine(
        self, tmp_path: Path, max_calls: int = 3, window: str = "60s"
    ) -> tuple[PolicyEngine, Path]:
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["api_call"],
                        action="allow",
                        rate_limit=RateLimit(
                            max_calls=max_calls, window=window
                        ),
                    ),
                ],
            ),
            rate_limit_backend=backend,
        )
        return engine, db

    def test_within_rate_limit(self, tmp_path: Path) -> None:
        engine, _ = self._make_engine(tmp_path, max_calls=3)
        tc = ToolCall(tool_name="api_call", arguments={})
        for _ in range(3):
            decision = engine.evaluate(tc)
            assert decision.allowed is True

    def test_exceeds_rate_limit(self, tmp_path: Path) -> None:
        engine, _ = self._make_engine(tmp_path, max_calls=2)
        tc = ToolCall(tool_name="api_call", arguments={})
        engine.evaluate(tc)
        engine.evaluate(tc)
        with pytest.raises(RateLimitExceeded):
            engine.evaluate(tc)

    def test_persists_across_engine_restart(self, tmp_path: Path) -> None:
        """Rate limits survive when the engine is recreated with the same db."""
        db = tmp_path / "rl.db"

        def make_engine() -> PolicyEngine:
            return PolicyEngine(
                PolicyConfig(
                    default_action="deny",
                    policies=[
                        PolicyRule(
                            name="limited",
                            tools=["api_call"],
                            action="allow",
                            rate_limit=RateLimit(
                                max_calls=3, window="60s"
                            ),
                        ),
                    ],
                ),
                rate_limit_backend=SQLiteBackend(db),
            )

        tc = ToolCall(tool_name="api_call", arguments={})

        # First engine: use 2 of 3 calls
        engine1 = make_engine()
        engine1.evaluate(tc)
        engine1.evaluate(tc)
        engine1._backend.close()

        # Second engine: should only have 1 call left
        engine2 = make_engine()
        engine2.evaluate(tc)  # 3rd call - should still be allowed
        with pytest.raises(RateLimitExceeded):
            engine2.evaluate(tc)  # 4th call - should be denied
        engine2._backend.close()

    def test_persists_across_restart_with_glob_tools(
        self, tmp_path: Path
    ) -> None:
        """Rate limits survive restart even when rules use glob patterns."""
        db = tmp_path / "rl.db"

        def make_engine() -> PolicyEngine:
            return PolicyEngine(
                PolicyConfig(
                    default_action="deny",
                    policies=[
                        PolicyRule(
                            name="limited",
                            tools=["*"],
                            action="allow",
                            rate_limit=RateLimit(
                                max_calls=2, window="60s"
                            ),
                        ),
                    ],
                ),
                rate_limit_backend=SQLiteBackend(db),
            )

        # First engine: use 1 call for tool_a
        engine1 = make_engine()
        engine1.evaluate(ToolCall(tool_name="tool_a", arguments={}))
        engine1._backend.close()

        # Second engine: hydrates from DB, tool_a should have 1 call used
        engine2 = make_engine()
        engine2.evaluate(ToolCall(tool_name="tool_a", arguments={}))  # 2nd
        with pytest.raises(RateLimitExceeded):
            engine2.evaluate(
                ToolCall(tool_name="tool_a", arguments={})
            )  # 3rd - denied
        # tool_b should still work (separate counter)
        engine2.evaluate(ToolCall(tool_name="tool_b", arguments={}))
        engine2._backend.close()

    def test_default_is_in_memory(self) -> None:
        """Without a backend argument the engine uses InMemoryBackend."""
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="r",
                        tools=["t"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=5, window="60s"),
                    ),
                ],
            ),
        )
        assert isinstance(engine._backend, InMemoryBackend)

    def test_per_tool_persistence(self, tmp_path: Path) -> None:
        """Different tools have separate persisted counters."""
        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        engine = PolicyEngine(
            PolicyConfig(
                default_action="deny",
                policies=[
                    PolicyRule(
                        name="limited",
                        tools=["*"],
                        action="allow",
                        rate_limit=RateLimit(max_calls=1, window="60s"),
                    ),
                ],
            ),
            rate_limit_backend=backend,
        )
        engine.evaluate(ToolCall(tool_name="tool_a", arguments={}))
        engine.evaluate(ToolCall(tool_name="tool_b", arguments={}))
        with pytest.raises(RateLimitExceeded):
            engine.evaluate(ToolCall(tool_name="tool_a", arguments={}))
        backend.close()


# ---------------------------------------------------------------------------
# Guard + SQLiteBackend integration
# ---------------------------------------------------------------------------


class TestGuardSQLiteIntegration:
    """Test that Guard correctly forwards rate_limit_backend."""

    def test_guard_with_sqlite_backend(self, tmp_path: Path) -> None:
        from avakill.core.engine import Guard

        db = tmp_path / "rl.db"
        backend = SQLiteBackend(db)
        config = PolicyConfig(
            default_action="deny",
            policies=[
                PolicyRule(
                    name="limited",
                    tools=["api_call"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=2, window="60s"),
                ),
            ],
        )
        guard = Guard(
            policy=config,
            self_protection=False,
            rate_limit_backend=backend,
        )
        guard.evaluate(tool="api_call", args={})
        guard.evaluate(tool="api_call", args={})
        with pytest.raises(RateLimitExceeded):
            guard.evaluate(tool="api_call", args={})
        backend.close()

    def test_guard_persists_across_restart(self, tmp_path: Path) -> None:
        from avakill.core.engine import Guard

        db = tmp_path / "rl.db"
        config = PolicyConfig(
            default_action="deny",
            policies=[
                PolicyRule(
                    name="limited",
                    tools=["api_call"],
                    action="allow",
                    rate_limit=RateLimit(max_calls=3, window="60s"),
                ),
            ],
        )

        # First guard: use 2 of 3 calls
        backend1 = SQLiteBackend(db)
        guard1 = Guard(
            policy=config,
            self_protection=False,
            rate_limit_backend=backend1,
        )
        guard1.evaluate(tool="api_call", args={})
        guard1.evaluate(tool="api_call", args={})
        backend1.close()

        # Second guard: should only have 1 call left
        backend2 = SQLiteBackend(db)
        guard2 = Guard(
            policy=config,
            self_protection=False,
            rate_limit_backend=backend2,
        )
        guard2.evaluate(tool="api_call", args={})  # 3rd - allowed
        with pytest.raises(RateLimitExceeded):
            guard2.evaluate(tool="api_call", args={})  # 4th - denied
        backend2.close()
