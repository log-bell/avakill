"""T5 content scanning engine for AvaKill.

Scans tool call argument values for secrets (API keys, tokens, private keys)
and prompt injection patterns using pre-compiled regexes and Shannon entropy
scoring.  All functions are pure — no file I/O during evaluation.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentMatch:
    """A single content scan finding.

    Attributes:
        scan_type: Category of scan that triggered (``"secrets"`` or
            ``"prompt_injection"``).
        pattern_name: Identifier for the specific pattern (e.g.
            ``"aws_access_key"``).
        matched_value: The offending substring, truncated to 40 chars.
        confidence: Confidence score between 0.0 and 1.0.
    """

    scan_type: str
    pattern_name: str
    matched_value: str
    confidence: float


# ---------------------------------------------------------------------------
# Secret patterns (pre-compiled)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # AWS access key IDs
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", 1.0),
    # GitHub personal access tokens (classic & fine-grained)
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github_pat", 1.0),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "github_oauth", 1.0),
    (re.compile(r"ghs_[a-zA-Z0-9]{36}"), "github_server", 1.0),
    (re.compile(r"ghu_[a-zA-Z0-9]{36}"), "github_user", 1.0),
    (re.compile(r"github_pat_[a-zA-Z0-9]{22,}"), "github_fine_grained", 1.0),
    # Stripe live keys
    (re.compile(r"sk_live_[a-zA-Z0-9]{20,}"), "stripe_secret", 1.0),
    (re.compile(r"rk_live_[a-zA-Z0-9]{20,}"), "stripe_restricted", 1.0),
    # Generic API keys (OpenAI-style sk-...)
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "generic_api_key", 0.8),
    # PEM private keys
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "private_key",
        1.0,
    ),
    # Bearer tokens
    (re.compile(r"Bearer [a-zA-Z0-9._\-]{20,}"), "bearer_token", 0.8),
]

# ---------------------------------------------------------------------------
# Prompt injection patterns (pre-compiled)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
        "ignore_instructions",
        0.9,
    ),
    (
        re.compile(
            r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
            re.IGNORECASE,
        ),
        "disregard_instructions",
        0.9,
    ),
    (
        re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
        "role_override",
        0.7,
    ),
    (
        re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
        "new_instructions",
        0.8,
    ),
    (
        re.compile(r"system\s+prompt\s*:", re.IGNORECASE),
        "system_prompt_leak",
        0.9,
    ),
    (
        re.compile(r"\bjailbreak\b", re.IGNORECASE),
        "jailbreak",
        0.7,
    ),
    (
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        "system_tag_open",
        0.8,
    ),
    (
        re.compile(r"act\s+as\s+(?:a\s+)?(?:different|new|another)\b", re.IGNORECASE),
        "act_as_override",
        0.7,
    ),
]

# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------

# Character class for hex strings (the primary entropy target)
_HEX_CHARS = set("0123456789abcdefABCDEF")

# Minimum length and entropy threshold for flagging.
# Max Shannon entropy for hex (16 symbols) is log2(16) = 4.0.
# Threshold 3.5 catches random-looking hex while allowing structured
# patterns like UUIDs (which typically score ~3.0-3.3).
# Min length 48 avoids false positives on git SHAs (40 chars) and
# certificate fingerprints while catching long secret material.
_MIN_ENTROPY_LENGTH = 48
_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character.

    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_high_entropy_secret(token: str) -> bool:
    """Return True if *token* looks like a high-entropy secret.

    Only triggers when the string ALSO matches a structural pattern:
    - Length >= 20 characters
    - At least 80% of *actual characters* (not unique set) are hex
    - Shannon entropy >= threshold (3.5 bits/char)

    This targets hex-encoded secrets while avoiding false positives
    on English text, UUIDs, and test/placeholder strings.
    """
    if len(token) < _MIN_ENTROPY_LENGTH:
        return False

    # Check actual character frequency, not unique character set.
    # This prevents flagging strings like "sk_test_abcdef..." where
    # most characters are alphabetic but not hex.
    hex_count = sum(1 for c in token if c in _HEX_CHARS)
    hex_ratio = hex_count / len(token)

    if hex_ratio < 0.8:
        return False

    return _shannon_entropy(token) >= _ENTROPY_THRESHOLD


# Pre-compiled pattern for extracting candidate tokens for entropy check.
# Matches sequences of alphanumeric + base64 chars of length >= 20.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


# ---------------------------------------------------------------------------
# Public scanning API
# ---------------------------------------------------------------------------


def scan_secrets(text: str) -> list[ContentMatch]:
    """Scan *text* for known secret patterns and high-entropy tokens.

    Args:
        text: The string to scan (typically an argument value).

    Returns:
        List of :class:`ContentMatch` findings, possibly empty.
    """
    if not text:
        return []

    matches: list[ContentMatch] = []

    # Regex-based detection
    for pattern, name, confidence in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            matched = m.group()
            truncated = matched[:40] + ("..." if len(matched) > 40 else "")
            matches.append(
                ContentMatch(
                    scan_type="secrets",
                    pattern_name=name,
                    matched_value=truncated,
                    confidence=confidence,
                )
            )

    # Entropy-based supplement (only if no regex already matched)
    if not matches:
        for token_match in _TOKEN_PATTERN.finditer(text):
            token = token_match.group()
            if _is_high_entropy_secret(token):
                truncated = token[:40] + ("..." if len(token) > 40 else "")
                matches.append(
                    ContentMatch(
                        scan_type="secrets",
                        pattern_name="high_entropy",
                        matched_value=truncated,
                        confidence=0.6,
                    )
                )
                break  # One entropy match is enough

    return matches


def scan_prompt_injection(text: str) -> list[ContentMatch]:
    """Scan *text* for prompt injection patterns.

    Args:
        text: The string to scan (typically an argument value).

    Returns:
        List of :class:`ContentMatch` findings, possibly empty.
    """
    if not text:
        return []

    matches: list[ContentMatch] = []
    for pattern, name, confidence in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            matched = m.group()
            truncated = matched[:40] + ("..." if len(matched) > 40 else "")
            matches.append(
                ContentMatch(
                    scan_type="prompt_injection",
                    pattern_name=name,
                    matched_value=truncated,
                    confidence=confidence,
                )
            )

    return matches


def scan_content(text: str, scan_types: list[str]) -> list[ContentMatch]:
    """Run selected scanners on *text*.

    Args:
        text: The string to scan.
        scan_types: List of scanner names to run. Supported values:
            ``"secrets"`` and ``"prompt_injection"``.

    Returns:
        Combined list of :class:`ContentMatch` findings from all requested
        scanners.
    """
    results: list[ContentMatch] = []
    for scan_type in scan_types:
        if scan_type == "secrets":
            results.extend(scan_secrets(text))
        elif scan_type == "prompt_injection":
            results.extend(scan_prompt_injection(text))
    return results
