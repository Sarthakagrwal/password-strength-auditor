"""Combine the naive charset model with the realistic ``zxcvbn`` estimator.

Two very different estimates are produced for every password:

* **Naive charset entropy** (:mod:`pwaudit.entropy`) — assumes the password is a
  uniformly random string drawn from its character pool. This *overestimates*
  real-world strength because human-chosen passwords are highly non-random:
  ``"Password123!"`` scores ~78 "bits" by this model yet is trivially guessed.

* **zxcvbn estimate** — the open-source estimator from Dropbox. It searches for
  dictionary words, names, dates, keyboard patterns, l33t substitutions and
  repeats, and reports the *guesses* an informed attacker actually needs. Its
  ``score`` (0–4) is the number this tool treats as trustworthy.

The README expands on why zxcvbn is the number to trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zxcvbn import zxcvbn

from pwaudit.entropy import CharsetAnalysis, analyze_charset, crack_times

# Human-readable label for each zxcvbn 0-4 score.
SCORE_LABELS: dict[int, str] = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very strong",
}

# zxcvbn's crack-time keys mapped to the four scenarios this tool reports.
_ZXCVBN_CRACK_KEYS: dict[str, str] = {
    "online_throttling_100_per_hour": "online_throttled",
    "online_no_throttling_10_per_second": "online_unthrottled",
    "offline_slow_hashing_1e4_per_second": "offline_slow_hash",
    "offline_fast_hashing_1e10_per_second": "offline_fast_hash",
}


@dataclass(frozen=True)
class ZxcvbnEstimate:
    """The subset of ``zxcvbn`` output this tool reports.

    The candidate password is deliberately **not** stored on this object; only
    the derived metrics are kept.
    """

    score: int
    score_label: str
    guesses: float
    guesses_log10: float
    crack_times_display: dict[str, str]
    warning: str
    suggestions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StrengthResult:
    """Combined strength analysis: naive charset model plus ``zxcvbn``."""

    charset: CharsetAnalysis
    naive_entropy_bits: float
    naive_crack_times: dict[str, str]
    zxcvbn: ZxcvbnEstimate

    @property
    def score(self) -> int:
        """The trustworthy 0-4 score — taken directly from ``zxcvbn``."""
        return self.zxcvbn.score


def _run_zxcvbn(password: str) -> ZxcvbnEstimate:
    """Run ``zxcvbn`` on *password* and project it onto :class:`ZxcvbnEstimate`.

    ``zxcvbn`` echoes the password back in its result dict; that field is
    discarded here so the password never propagates into this tool's report.
    """
    raw = zxcvbn(password)
    score = int(raw["score"])
    feedback = raw.get("feedback", {}) or {}

    # Re-key zxcvbn's crack-time display strings to this tool's scenario names.
    display: dict[str, str] = {}
    raw_display = raw.get("crack_times_display", {}) or {}
    for zxcvbn_key, our_key in _ZXCVBN_CRACK_KEYS.items():
        if zxcvbn_key in raw_display:
            display[our_key] = str(raw_display[zxcvbn_key])

    return ZxcvbnEstimate(
        score=score,
        score_label=SCORE_LABELS.get(score, "Unknown"),
        guesses=float(raw.get("guesses", 0.0)),
        guesses_log10=float(raw.get("guesses_log10", 0.0)),
        crack_times_display=display,
        warning=str(feedback.get("warning", "") or ""),
        suggestions=[str(s) for s in (feedback.get("suggestions", []) or [])],
    )


def analyze_strength(password: str) -> StrengthResult:
    """Produce the combined strength analysis for *password*.

    Computes the naive charset entropy and its crack-time projections, runs
    ``zxcvbn``, and bundles both into a single :class:`StrengthResult`. The
    authoritative score is ``result.score`` (the ``zxcvbn`` 0-4 score).
    """
    charset = analyze_charset(password)
    naive_bits = charset.entropy_bits
    return StrengthResult(
        charset=charset,
        naive_entropy_bits=naive_bits,
        naive_crack_times=crack_times(naive_bits),
        zxcvbn=_run_zxcvbn(password),
    )
