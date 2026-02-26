"""Cross-call correlation pattern matching for T4.

Defines sequence and burst patterns, and a matcher that checks a
SessionRing against all registered patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avakill.core.session_store import SessionRing


@dataclass(frozen=True)
class CorrelationPattern:
    """An ordered sequence of tag requirements.

    Matches when the required tags appear as an ordered subsequence
    within the last ``max_window_calls`` entries of a session ring.

    Attributes:
        name: Human-readable pattern name.
        steps: Ordered list of tags that must appear in sequence.
        max_window_calls: Only consider the last N calls in the ring.
    """

    name: str
    steps: tuple[str, ...]
    max_window_calls: int = 30


@dataclass(frozen=True)
class BurstPattern:
    """A count-in-window burst pattern.

    Matches when a single tag appears at least ``threshold`` times
    within ``window_seconds``.

    Attributes:
        name: Human-readable pattern name.
        tag: The tag to count.
        threshold: Minimum count to trigger.
        window_seconds: Time window in seconds.
    """

    name: str
    tag: str
    threshold: int
    window_seconds: float


@dataclass(frozen=True)
class CorrelationMatch:
    """Result of a successful pattern match.

    Attributes:
        pattern_name: Name of the matched pattern.
        matched_tags: The tags that contributed to the match.
    """

    pattern_name: str
    matched_tags: tuple[str, ...]


class CorrelationMatcher:
    """Checks a SessionRing against registered sequence and burst patterns."""

    def __init__(
        self,
        patterns: list[CorrelationPattern] | None = None,
        burst_patterns: list[BurstPattern] | None = None,
    ) -> None:
        self._patterns: list[CorrelationPattern] = list(patterns or [])
        self._burst_patterns: list[BurstPattern] = list(burst_patterns or [])

    def check(self, ring: SessionRing) -> CorrelationMatch | None:
        """Check the ring against all patterns. Return first match or None."""
        for pattern in self._patterns:
            match = self._match_pattern(ring, pattern)
            if match is not None:
                return match
        for burst in self._burst_patterns:
            match = self._match_burst(ring, burst)
            if match is not None:
                return match
        return None

    def _match_pattern(
        self, ring: SessionRing, pattern: CorrelationPattern
    ) -> CorrelationMatch | None:
        """Ordered subsequence matching within the window."""
        entries = ring.entries
        # Only consider the last max_window_calls entries
        if len(entries) > pattern.max_window_calls:
            entries = entries[-pattern.max_window_calls :]

        step_idx = 0
        matched_tags: list[str] = []

        for entry in entries:
            if step_idx >= len(pattern.steps):
                break
            required_tag = pattern.steps[step_idx]
            if required_tag in entry.tags:
                matched_tags.append(required_tag)
                step_idx += 1

        if step_idx >= len(pattern.steps):
            return CorrelationMatch(
                pattern_name=pattern.name,
                matched_tags=tuple(matched_tags),
            )
        return None

    def _match_burst(self, ring: SessionRing, burst: BurstPattern) -> CorrelationMatch | None:
        """Count-in-window matching for burst patterns."""
        entries = ring.entries
        if not entries:
            return None

        # Use the latest entry's timestamp as the reference
        latest_ts = entries[-1].timestamp
        window_start = latest_ts - burst.window_seconds

        count = 0
        for entry in entries:
            if entry.timestamp >= window_start and burst.tag in entry.tags:
                count += 1

        if count >= burst.threshold:
            return CorrelationMatch(
                pattern_name=burst.name,
                matched_tags=(burst.tag,) * count,
            )
        return None


# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------

PATTERN_ENCODE_TRANSMIT = CorrelationPattern(
    name="encode-transmit",
    steps=("secret_access", "encode", "network_transmit"),
)

PATTERN_CREDENTIAL_EXFIL = CorrelationPattern(
    name="credential-exfil",
    steps=("secret_access", "network_transmit"),
)

PATTERN_CLIPBOARD_EXFIL = CorrelationPattern(
    name="clipboard-exfil",
    steps=("secret_access", "clipboard_write"),
)

PATTERN_RAPID_DELETION = BurstPattern(
    name="rapid-deletion",
    tag="file_delete",
    threshold=5,
    window_seconds=60.0,
)

DEFAULT_PATTERNS: list[CorrelationPattern] = [
    PATTERN_ENCODE_TRANSMIT,
    PATTERN_CREDENTIAL_EXFIL,
    PATTERN_CLIPBOARD_EXFIL,
]

DEFAULT_BURST_PATTERNS: list[BurstPattern] = [
    PATTERN_RAPID_DELETION,
]
