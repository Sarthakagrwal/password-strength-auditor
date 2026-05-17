"""Charset-pool entropy estimation and crack-time projections.

This module implements the classic, *naive* model of password strength:

1. Detect which character classes appear in the password.
2. Sum the sizes of those classes into a single "search-space pool".
3. ``entropy_bits = length * log2(pool)`` — the bits of entropy assuming every
   character is chosen uniformly at random from that pool.
4. The number of guesses to exhaust that space is ``2 ** entropy_bits``; divide
   by documented attacker guess rates to project a crack time.

This model is deliberately optimistic — it assumes the password is random. Real
passwords are not, which is why :mod:`pwaudit.strength` also reports the
``zxcvbn`` estimate. See the project README for the full explanation.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass

# --- Character-class pool sizes -------------------------------------------------
# Symbol pool size: printable ASCII punctuation (string.punctuation) has 32
# characters; we add the space character, giving 33 — a widely used figure.
LOWERCASE_POOL = 26
UPPERCASE_POOL = 26
DIGIT_POOL = 10
SYMBOL_POOL = 33

_LOWER = set(string.ascii_lowercase)
_UPPER = set(string.ascii_uppercase)
_DIGITS = set(string.digits)
# The "symbols" class is detected by exclusion (anything not lower/upper/digit),
# so it needs no explicit set — that also catches non-ASCII characters.


# --- Documented attacker guess rates (guesses per second) -----------------------
# These are order-of-magnitude figures commonly cited in password-security
# guidance; they are illustrative, not guarantees.
GUESS_RATES: dict[str, float] = {
    # An online login form that throttles / rate-limits attempts.
    "online_throttled": 1e1,  # ~10 guesses/sec
    # An online service with no throttling at all.
    "online_unthrottled": 1e3,  # ~1,000 guesses/sec
    # Offline attack against a fast hash (e.g. unsalted MD5/SHA-1) on a GPU rig.
    "offline_fast_hash": 1e10,  # ~10 billion guesses/sec
    # Offline attack against a deliberately slow hash (bcrypt / Argon2).
    "offline_slow_hash": 1e4,  # ~10,000 guesses/sec
}

# Human-readable labels for each scenario, in a sensible reporting order.
SCENARIO_LABELS: dict[str, str] = {
    "online_throttled": "Online attack, rate-limited (~10/s)",
    "online_unthrottled": "Online attack, no rate limit (~1e3/s)",
    "offline_slow_hash": "Offline attack, slow hash / bcrypt (~1e4/s)",
    "offline_fast_hash": "Offline attack, fast hash on GPU (~1e10/s)",
}

_REPORT_ORDER = (
    "online_throttled",
    "online_unthrottled",
    "offline_slow_hash",
    "offline_fast_hash",
)


@dataclass(frozen=True)
class CharsetAnalysis:
    """Result of analysing which character classes a password uses."""

    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    pool_size: int
    length: int
    entropy_bits: float

    @property
    def classes_used(self) -> int:
        """Number of distinct character classes present in the password."""
        return sum((self.has_lowercase, self.has_uppercase, self.has_digits, self.has_symbols))


def detect_charset(password: str) -> tuple[bool, bool, bool, bool]:
    """Detect which character classes are present in *password*.

    Returns a 4-tuple of booleans:
    ``(has_lowercase, has_uppercase, has_digits, has_symbols)``.

    Any character that is not lowercase, uppercase or a digit is counted toward
    the "symbols" class — this includes punctuation, spaces and any non-ASCII
    character a user might type.
    """
    has_lower = any(c in _LOWER for c in password)
    has_upper = any(c in _UPPER for c in password)
    has_digit = any(c in _DIGITS for c in password)
    # Symbols: anything that is not in the three named ASCII classes.
    has_symbol = any((c not in _LOWER and c not in _UPPER and c not in _DIGITS) for c in password)
    return has_lower, has_upper, has_digit, has_symbol


def charset_pool_size(password: str) -> int:
    """Return the combined search-space pool size for *password*.

    The pool is the sum of the sizes of every character class that appears at
    least once. For example ``"Ab1"`` uses lowercase + uppercase + digits, so
    the pool is ``26 + 26 + 10 = 62``.
    """
    has_lower, has_upper, has_digit, has_symbol = detect_charset(password)
    pool = 0
    if has_lower:
        pool += LOWERCASE_POOL
    if has_upper:
        pool += UPPERCASE_POOL
    if has_digit:
        pool += DIGIT_POOL
    if has_symbol:
        pool += SYMBOL_POOL
    return pool


def entropy_bits(password: str) -> float:
    """Return the naive charset-pool entropy of *password* in bits.

    ``entropy_bits = length * log2(pool_size)``. An empty password, or one whose
    pool somehow resolves to zero, has zero bits of entropy.
    """
    pool = charset_pool_size(password)
    if pool <= 1 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def analyze_charset(password: str) -> CharsetAnalysis:
    """Run the full charset analysis for *password* and return a dataclass."""
    has_lower, has_upper, has_digit, has_symbol = detect_charset(password)
    pool = charset_pool_size(password)
    return CharsetAnalysis(
        has_lowercase=has_lower,
        has_uppercase=has_upper,
        has_digits=has_digit,
        has_symbols=has_symbol,
        pool_size=pool,
        length=len(password),
        entropy_bits=entropy_bits(password),
    )


# Largest exponent for which 2.0 ** exponent is still a finite float64 value.
_MAX_SAFE_BITS = 1023.0


def guesses_for_bits(bits: float) -> float:
    """Return the number of guesses (``2 ** bits``) implied by an entropy value.

    Capped at the largest finite float64 power of two to avoid ``OverflowError``
    for absurd inputs; any password long enough to hit the cap is, for reporting
    purposes, effectively uncrackable anyway.
    """
    if bits <= 0:
        return 1.0
    # 2 ** 1024 overflows float64; clamp so the result stays finite.
    capped = min(bits, _MAX_SAFE_BITS)
    return 2.0**capped


# Time units as (size-in-seconds, singular-name), smallest to largest.
_MINUTE = 60.0
_HOUR = 60.0 * _MINUTE
_DAY = 24.0 * _HOUR
_MONTH = 30.0 * _DAY
_YEAR = 365.0 * _DAY
_CENTURY = 100.0 * _YEAR

_TIME_UNITS: tuple[tuple[float, str], ...] = (
    (1.0, "second"),
    (_MINUTE, "minute"),
    (_HOUR, "hour"),
    (_DAY, "day"),
    (_MONTH, "month"),
    (_YEAR, "year"),
    (_CENTURY, "century"),
)


def _pluralize(count: int, singular: str) -> str:
    """Return ``"<count> <unit>"`` with English pluralisation of *singular*."""
    if count == 1:
        return f"1 {singular}"
    if singular == "century":
        return f"{count} centuries"
    return f"{count} {singular}s"


def format_duration(seconds: float) -> str:
    """Format a duration in *seconds* as a compact human-readable string.

    Examples: ``"instantly"``, ``"3 minutes"``, ``"2 days"``, ``"14 centuries"``,
    ``"5e+07 years"``. The largest unit for which the value rounds to under 1000
    is chosen; durations beyond that fall back to scientific-notation years.
    """
    if seconds < 1:
        return "instantly"

    # Beyond ~100,000 years any named unit is unwieldy: use scientific years.
    if seconds / _YEAR >= 1e5:
        return f"{seconds / _YEAR:.0e} years"

    # Pick the largest unit whose value is at least 1, so 90s reads as
    # "2 minutes" rather than a tiny fraction of a century.
    for size, name in reversed(_TIME_UNITS):
        value = seconds / size
        if value >= 1:
            return _pluralize(round(value), name)

    return _pluralize(round(seconds), "second")


def crack_times(bits: float) -> dict[str, str]:
    """Project crack times for an entropy value across all attacker scenarios.

    Returns an ordered mapping ``{scenario_key: human_readable_duration}``. The
    keys follow :data:`SCENARIO_LABELS`; use that mapping for display labels.

    The estimate assumes an attacker must search, on average, half the keyspace,
    so the guess count is ``2 ** bits / 2``.
    """
    total_guesses = guesses_for_bits(bits)
    average_guesses = total_guesses / 2.0
    result: dict[str, str] = {}
    for key in _REPORT_ORDER:
        rate = GUESS_RATES[key]
        seconds = average_guesses / rate
        result[key] = format_duration(seconds)
    return result
