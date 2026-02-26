"""Tests for avakill.core.correlation — pattern matching for T4."""

from __future__ import annotations

from avakill.core.correlation import (
    DEFAULT_BURST_PATTERNS,
    DEFAULT_PATTERNS,
    PATTERN_CLIPBOARD_EXFIL,
    PATTERN_CREDENTIAL_EXFIL,
    PATTERN_ENCODE_TRANSMIT,
    PATTERN_RAPID_DELETION,
    CorrelationMatcher,
    CorrelationPattern,
)
from avakill.core.session_store import SessionRing, TaggedCall


def _make_ring(entries: list[tuple[frozenset[str], float]]) -> SessionRing:
    """Helper to build a ring from (tags, timestamp) pairs."""
    ring = SessionRing(max_size=50)
    for tags, ts in entries:
        ring.append(TaggedCall(tool_name="t", tags=tags, timestamp=ts))
    return ring


class TestCorrelationMatcher:
    def test_encode_transmit_matches(self):
        """secret_access -> encode -> network_transmit should match."""
        matcher = CorrelationMatcher(patterns=[PATTERN_ENCODE_TRANSMIT])
        ring = _make_ring(
            [
                (frozenset({"secret_access", "credential_read", "file_read"}), 1.0),
                (frozenset({"encode", "shell_exec"}), 2.0),
                (frozenset({"network_transmit"}), 3.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        assert match.pattern_name == "encode-transmit"
        assert match.matched_tags == ("secret_access", "encode", "network_transmit")

    def test_wrong_order_rejects(self):
        """network_transmit -> encode -> secret_access should NOT match."""
        matcher = CorrelationMatcher(patterns=[PATTERN_ENCODE_TRANSMIT])
        ring = _make_ring(
            [
                (frozenset({"network_transmit"}), 1.0),
                (frozenset({"encode"}), 2.0),
                (frozenset({"secret_access"}), 3.0),
            ]
        )
        assert matcher.check(ring) is None

    def test_missing_step_rejects(self):
        """secret_access -> network_transmit (no encode) shouldn't match encode-transmit."""
        matcher = CorrelationMatcher(patterns=[PATTERN_ENCODE_TRANSMIT])
        ring = _make_ring(
            [
                (frozenset({"secret_access"}), 1.0),
                (frozenset({"network_transmit"}), 2.0),
            ]
        )
        assert matcher.check(ring) is None

    def test_window_enforcement(self):
        """Pattern outside max_window_calls should not match."""
        short_window = CorrelationPattern(
            name="short-window",
            steps=("secret_access", "encode", "network_transmit"),
            max_window_calls=2,
        )
        matcher = CorrelationMatcher(patterns=[short_window])
        ring = _make_ring(
            [
                (frozenset({"secret_access"}), 1.0),
                (frozenset({"encode"}), 2.0),
                (frozenset({"network_transmit"}), 3.0),
            ]
        )
        # Window of 2 only sees last 2 entries: encode + network_transmit
        # secret_access is outside the window
        assert matcher.check(ring) is None

    def test_credential_exfil_matches(self):
        """secret_access -> network_transmit matches credential-exfil."""
        matcher = CorrelationMatcher(patterns=[PATTERN_CREDENTIAL_EXFIL])
        ring = _make_ring(
            [
                (frozenset({"secret_access"}), 1.0),
                (frozenset({"network_transmit"}), 2.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        assert match.pattern_name == "credential-exfil"

    def test_clipboard_exfil_matches(self):
        """secret_access -> clipboard_write matches clipboard-exfil."""
        matcher = CorrelationMatcher(patterns=[PATTERN_CLIPBOARD_EXFIL])
        ring = _make_ring(
            [
                (frozenset({"secret_access", "credential_read"}), 1.0),
                (frozenset({"clipboard_write"}), 2.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        assert match.pattern_name == "clipboard-exfil"

    def test_burst_detection_rapid_deletion(self):
        """5 file_delete within 60s should trigger rapid-deletion."""
        matcher = CorrelationMatcher(burst_patterns=[PATTERN_RAPID_DELETION])
        ring = _make_ring(
            [
                (frozenset({"file_delete"}), 100.0),
                (frozenset({"file_delete"}), 101.0),
                (frozenset({"file_delete"}), 102.0),
                (frozenset({"file_delete"}), 103.0),
                (frozenset({"file_delete"}), 104.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        assert match.pattern_name == "rapid-deletion"

    def test_burst_below_threshold_allows(self):
        """4 file_delete (below threshold of 5) should not match."""
        matcher = CorrelationMatcher(burst_patterns=[PATTERN_RAPID_DELETION])
        ring = _make_ring(
            [
                (frozenset({"file_delete"}), 100.0),
                (frozenset({"file_delete"}), 101.0),
                (frozenset({"file_delete"}), 102.0),
                (frozenset({"file_delete"}), 103.0),
            ]
        )
        assert matcher.check(ring) is None

    def test_burst_outside_window_allows(self):
        """5 file_delete spread over >60s should not match."""
        matcher = CorrelationMatcher(burst_patterns=[PATTERN_RAPID_DELETION])
        ring = _make_ring(
            [
                (frozenset({"file_delete"}), 1.0),
                (frozenset({"file_delete"}), 2.0),
                (frozenset({"file_delete"}), 3.0),
                (frozenset({"file_delete"}), 4.0),
                (frozenset({"file_delete"}), 100.0),  # Latest; window = 40-100
            ]
        )
        # Only the last entry is within 60s of itself; first 4 are at 1-4 (outside 40-100 window)
        assert matcher.check(ring) is None

    def test_interleaved_tags_still_match(self):
        """Non-matching tags between steps should not prevent match."""
        matcher = CorrelationMatcher(patterns=[PATTERN_ENCODE_TRANSMIT])
        ring = _make_ring(
            [
                (frozenset({"secret_access"}), 1.0),
                (frozenset({"file_read"}), 2.0),  # benign
                (frozenset({"shell_exec"}), 3.0),  # benign
                (frozenset({"encode"}), 4.0),
                (frozenset({"file_read"}), 5.0),  # benign
                (frozenset({"network_transmit"}), 6.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        assert match.pattern_name == "encode-transmit"

    def test_empty_ring_no_match(self):
        matcher = CorrelationMatcher(
            patterns=[PATTERN_ENCODE_TRANSMIT],
            burst_patterns=[PATTERN_RAPID_DELETION],
        )
        ring = SessionRing(max_size=50)
        assert matcher.check(ring) is None

    def test_first_pattern_wins(self):
        """When multiple patterns match, the first registered one wins."""
        matcher = CorrelationMatcher(patterns=[PATTERN_ENCODE_TRANSMIT, PATTERN_CREDENTIAL_EXFIL])
        ring = _make_ring(
            [
                (frozenset({"secret_access"}), 1.0),
                (frozenset({"encode"}), 2.0),
                (frozenset({"network_transmit"}), 3.0),
            ]
        )
        match = matcher.check(ring)
        assert match is not None
        # encode-transmit comes first and matches
        assert match.pattern_name == "encode-transmit"


class TestDefaultPatterns:
    def test_default_pattern_count(self):
        assert len(DEFAULT_PATTERNS) == 3

    def test_default_burst_pattern_count(self):
        assert len(DEFAULT_BURST_PATTERNS) == 1

    def test_pattern_names(self):
        names = {p.name for p in DEFAULT_PATTERNS}
        assert names == {"encode-transmit", "credential-exfil", "clipboard-exfil"}

    def test_burst_pattern_names(self):
        names = {p.name for p in DEFAULT_BURST_PATTERNS}
        assert names == {"rapid-deletion"}

    def test_all_patterns_are_frozen(self):
        for p in DEFAULT_PATTERNS:
            assert isinstance(p.steps, tuple)
        for b in DEFAULT_BURST_PATTERNS:
            assert isinstance(b.tag, str)
