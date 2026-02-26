"""Tests for avakill.core.session_store — bounded session state for T4."""

from __future__ import annotations

import threading
import time

from avakill.core.session_store import SessionRing, SessionStore, TaggedCall


class TestTaggedCall:
    def test_frozen(self):
        tc = TaggedCall(tool_name="Bash", tags=frozenset({"shell_exec"}), timestamp=1.0)
        assert tc.tool_name == "Bash"
        assert tc.tags == frozenset({"shell_exec"})
        assert tc.timestamp == 1.0

    def test_tags_are_frozenset(self):
        tc = TaggedCall(tool_name="Read", tags=frozenset({"file_read"}), timestamp=0.0)
        assert isinstance(tc.tags, frozenset)


class TestSessionRing:
    def test_append_and_len(self):
        ring = SessionRing(max_size=5)
        entry = TaggedCall(tool_name="Bash", tags=frozenset({"shell_exec"}), timestamp=1.0)
        ring.append(entry)
        assert len(ring) == 1
        assert ring.entries[0] is entry

    def test_eviction_at_max_size(self):
        ring = SessionRing(max_size=3)
        for i in range(5):
            ring.append(TaggedCall(tool_name=f"tool-{i}", tags=frozenset(), timestamp=float(i)))
        assert len(ring) == 3
        # Oldest two should be evicted
        assert ring.entries[0].tool_name == "tool-2"
        assert ring.entries[1].tool_name == "tool-3"
        assert ring.entries[2].tool_name == "tool-4"

    def test_last_activity_updates(self):
        ring = SessionRing(max_size=5)
        ring.append(TaggedCall(tool_name="a", tags=frozenset(), timestamp=10.0))
        assert ring.last_activity == 10.0
        ring.append(TaggedCall(tool_name="b", tags=frozenset(), timestamp=20.0))
        assert ring.last_activity == 20.0

    def test_tag_sequence(self):
        ring = SessionRing(max_size=10)
        ring.append(TaggedCall(tool_name="a", tags=frozenset({"x"}), timestamp=1.0))
        ring.append(TaggedCall(tool_name="b", tags=frozenset({"y", "z"}), timestamp=2.0))
        seq = ring.tag_sequence()
        assert seq == [frozenset({"x"}), frozenset({"y", "z"})]

    def test_entries_returns_copy(self):
        ring = SessionRing(max_size=5)
        ring.append(TaggedCall(tool_name="a", tags=frozenset(), timestamp=1.0))
        entries = ring.entries
        entries.clear()
        assert len(ring) == 1  # Original unaffected


class TestSessionStore:
    def test_record_creates_session(self):
        store = SessionStore(max_sessions=10)
        entry = TaggedCall(tool_name="Bash", tags=frozenset({"shell_exec"}), timestamp=1.0)
        ring = store.record("sess-1", entry)
        assert len(ring) == 1

    def test_record_appends_to_existing(self):
        store = SessionStore(max_sessions=10)
        e1 = TaggedCall(tool_name="a", tags=frozenset(), timestamp=1.0)
        e2 = TaggedCall(tool_name="b", tags=frozenset(), timestamp=2.0)
        store.record("sess-1", e1)
        ring = store.record("sess-1", e2)
        assert len(ring) == 2

    def test_max_sessions_eviction(self):
        store = SessionStore(max_sessions=3, ring_size=5)
        for i in range(5):
            store.record(
                f"sess-{i}",
                TaggedCall(tool_name="t", tags=frozenset(), timestamp=float(i)),
            )
        # Only last 3 should remain
        assert store.get("sess-0") is None
        assert store.get("sess-1") is None
        assert store.get("sess-2") is not None
        assert store.get("sess-3") is not None
        assert store.get("sess-4") is not None

    def test_ttl_eviction(self):
        store = SessionStore(max_sessions=10, ttl_seconds=100.0)
        # Force last_eviction to 0 so next call triggers eviction
        store._last_eviction = 0.0

        now = time.monotonic()
        # Record an old session (activity well before now)
        old_entry = TaggedCall(tool_name="t", tags=frozenset(), timestamp=now - 200.0)
        store.record("old-sess", old_entry)
        # Manually set the ring's last_activity to be expired
        ring = store.get("old-sess")
        assert ring is not None
        ring.last_activity = now - 200.0

        # Force next eviction check
        store._last_eviction = 0.0

        # Recording a new session should trigger eviction of the old one
        new_entry = TaggedCall(tool_name="t", tags=frozenset(), timestamp=now)
        store.record("new-sess", new_entry)

        assert store.get("old-sess") is None
        assert store.get("new-sess") is not None

    def test_get_returns_none_for_unknown(self):
        store = SessionStore()
        assert store.get("nonexistent") is None

    def test_clear(self):
        store = SessionStore()
        store.record(
            "sess-1",
            TaggedCall(tool_name="t", tags=frozenset(), timestamp=1.0),
        )
        store.clear()
        assert store.get("sess-1") is None

    def test_thread_safety(self):
        store = SessionStore(max_sessions=100)
        errors: list[Exception] = []

        def writer(session_prefix: str) -> None:
            try:
                for i in range(50):
                    store.record(
                        f"{session_prefix}-{i}",
                        TaggedCall(
                            tool_name="t",
                            tags=frozenset(),
                            timestamp=time.monotonic(),
                        ),
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(f"t{t}",)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
