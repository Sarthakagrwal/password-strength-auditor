"""Transparent password-weakness pattern detectors.

Each detector looks for one specific, well-understood weakness and, when it
fires, returns a :class:`PatternFinding` whose ``reason`` string explains in
plain language why the pattern hurts the password. These findings are *advisory
downgrade reasons*: they tell the user what to fix. They are deliberately simple
and explainable — unlike the statistical ``zxcvbn`` model, you can read this
file and understand exactly what every check does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pwaudit.common_passwords import is_common_password

# --- Keyboard rows used for "keyboard walk" detection ---------------------------
# Each string is one physical row of a QWERTY keyboard, lower-cased.
_KEYBOARD_ROWS: tuple[str, ...] = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

# Leetspeak substitution map: leet character -> the letter it commonly replaces.
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
    "(": "c",
}

# Minimum run length before a sequence / repeat / walk is considered a weakness.
_MIN_RUN = 4


@dataclass(frozen=True)
class PatternFinding:
    """A single detected weakness pattern.

    Attributes:
        code: A short stable identifier (e.g. ``"sequential"``), handy for tests
            and machine-readable output.
        reason: A human-readable explanation of the weakness.
    """

    code: str
    reason: str


def _has_sequential_run(password: str, min_run: int = _MIN_RUN) -> bool:
    """Return ``True`` if *password* contains an ascending or descending run.

    A "run" is ``min_run`` or more consecutive characters whose code points each
    differ from the previous by exactly +1 (ascending) or -1 (descending), e.g.
    ``abcd``, ``4321``, ``wxyz``. The check is case-insensitive.
    """
    pw = password.lower()
    if len(pw) < min_run:
        return False
    asc = desc = 1
    for i in range(1, len(pw)):
        delta = ord(pw[i]) - ord(pw[i - 1])
        asc = asc + 1 if delta == 1 else 1
        desc = desc + 1 if delta == -1 else 1
        if asc >= min_run or desc >= min_run:
            return True
    return False


def _has_repeat_run(password: str, min_run: int = _MIN_RUN) -> bool:
    """Return ``True`` if a single character repeats ``min_run`` times in a row.

    Example: ``aaaa`` or ``1111``. The check is case-insensitive.
    """
    pw = password.lower()
    if len(pw) < min_run:
        return False
    run = 1
    for i in range(1, len(pw)):
        run = run + 1 if pw[i] == pw[i - 1] else 1
        if run >= min_run:
            return True
    return False


def _has_keyboard_walk(password: str, min_run: int = _MIN_RUN) -> bool:
    """Return ``True`` if *password* contains a straight keyboard-row walk.

    A walk is ``min_run`` consecutive characters that appear adjacent, in order
    (forwards or backwards), on a single QWERTY row — e.g. ``qwer``, ``asdf``,
    ``rewq``. The check is case-insensitive.
    """
    pw = password.lower()
    if len(pw) < min_run:
        return False
    for row in _KEYBOARD_ROWS:
        reversed_row = row[::-1]
        for window_start in range(len(pw) - min_run + 1):
            window = pw[window_start : window_start + min_run]
            if window in row or window in reversed_row:
                return True
    return False


def _normalize_leet(password: str) -> str:
    """Replace leetspeak characters in *password* with their plain letters."""
    return "".join(_LEET_MAP.get(c, c) for c in password.lower())


def _is_leetspeak_of_common(password: str) -> str | None:
    """Detect leetspeak obfuscation of a common password.

    If *password* itself contains at least one leet character **and** its
    de-leeted form is a known common password, return that de-leeted word;
    otherwise return ``None``. Requiring an actual substitution avoids
    re-flagging a plain common password (that is reported separately).
    """
    has_leet_char = any(c in _LEET_MAP for c in password.lower())
    if not has_leet_char:
        return None
    normalized = _normalize_leet(password)
    if normalized != password.lower() and is_common_password(normalized):
        return normalized
    return None


# A 4-digit year from 1900 to the near future, used for "year in password".
_YEAR_RE = re.compile(r"(?:19\d\d|20[0-3]\d)")


def _contains_year(password: str) -> str | None:
    """Return the first plausible 4-digit year (1900–2039) found, or ``None``."""
    match = _YEAR_RE.search(password)
    return match.group(0) if match else None


def find_patterns(password: str) -> list[PatternFinding]:
    """Run every pattern detector against *password*.

    Returns a list of :class:`PatternFinding` objects, one per weakness found.
    An empty list means none of the transparent detectors fired (which does not
    by itself mean the password is strong — see :mod:`pwaudit.strength`).
    """
    findings: list[PatternFinding] = []
    if not password:
        return findings

    if is_common_password(password):
        findings.append(
            PatternFinding(
                "common_password",
                "This is one of the most common passwords in breach corpora — "
                "it would be guessed almost immediately.",
            )
        )

    leet_of = _is_leetspeak_of_common(password)
    if leet_of is not None:
        findings.append(
            PatternFinding(
                "leetspeak",
                f"This is leetspeak for the common password '{leet_of}'. "
                "Character swaps like a->@ or o->0 are the first thing crackers try.",
            )
        )

    if _has_sequential_run(password):
        findings.append(
            PatternFinding(
                "sequential",
                "Contains a sequential run (e.g. 'abcd' or '1234'). "
                "Sequences add almost no real randomness.",
            )
        )

    if _has_repeat_run(password):
        findings.append(
            PatternFinding(
                "repeat",
                "Contains a character repeated four or more times in a row "
                "(e.g. 'aaaa'). Repeats barely expand the search space.",
            )
        )

    if _has_keyboard_walk(password):
        findings.append(
            PatternFinding(
                "keyboard_walk",
                "Contains a keyboard walk (e.g. 'qwerty' or 'asdf'). "
                "Adjacent-key patterns are in every cracking wordlist.",
            )
        )

    year = _contains_year(password)
    if year is not None:
        findings.append(
            PatternFinding(
                "year",
                f"Contains the year '{year}'. Years (birthdays, graduations) "
                "are highly predictable and heavily targeted.",
            )
        )

    return findings
