"""Top-level audit orchestration.

:func:`audit` runs the full pipeline — charset entropy, pattern detectors,
``zxcvbn`` estimate, and (optionally) the HIBP breach check — and folds the
results into a single :class:`AuditReport` with an overall verdict.

The overriding rule
-------------------
**A password found in a breach is reported UNSAFE regardless of its strength
score.** Once a password is in a public breach corpus, attackers already have
it: it sits at the top of every credential-stuffing wordlist. No amount of
length or entropy undoes that exposure, so breach presence overrides the
strength verdict. The README explains this in full.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pwaudit.hibp import check_password
from pwaudit.patterns import PatternFinding, find_patterns
from pwaudit.strength import StrengthResult, analyze_strength

# Verdict strings used across the CLI, tests and (mirrored) the website.
VERDICT_SAFE = "SAFE"
VERDICT_WEAK = "WEAK"
VERDICT_UNSAFE = "UNSAFE"

# Risk band for the verdict, aligned with the shared green/amber/red scale.
RISK_SAFE = "safe"
RISK_WARN = "warn"
RISK_DANGER = "danger"


@dataclass(frozen=True)
class AuditReport:
    """The complete result of auditing one password.

    The candidate password is intentionally **absent** from this object — only
    derived, non-sensitive metrics are stored, so an :class:`AuditReport` is
    safe to print, serialise to JSON or log.
    """

    score: int
    score_label: str
    verdict: str
    risk: str
    summary: str
    strength: StrengthResult
    patterns: list[PatternFinding] = field(default_factory=list)
    breach_count: int | None = None
    hibp_checked: bool = True

    @property
    def breached(self) -> bool:
        """``True`` only if HIBP confirmed the password appears in a breach."""
        return self.breach_count is not None and self.breach_count > 0

    @property
    def breach_status(self) -> str:
        """Human-readable breach status line."""
        if not self.hibp_checked:
            return "Not checked (offline mode)"
        if self.breach_count is None:
            return "Unavailable (could not reach Have I Been Pwned)"
        if self.breach_count == 0:
            return "Not found in any known breach"
        times = "time" if self.breach_count == 1 else "times"
        return f"Found in known breaches {self.breach_count:,} {times}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dict of the report (no password)."""
        z = self.strength.zxcvbn
        return {
            "verdict": self.verdict,
            "risk": self.risk,
            "score": self.score,
            "score_label": self.score_label,
            "summary": self.summary,
            "naive_entropy_bits": round(self.strength.naive_entropy_bits, 1),
            "naive_crack_times": self.strength.naive_crack_times,
            "zxcvbn": {
                "score": z.score,
                "guesses_log10": round(z.guesses_log10, 1),
                "crack_times": z.crack_times_display,
                "warning": z.warning,
                "suggestions": z.suggestions,
            },
            "charset": {
                "length": self.strength.charset.length,
                "pool_size": self.strength.charset.pool_size,
                "classes_used": self.strength.charset.classes_used,
            },
            "patterns": [{"code": f.code, "reason": f.reason} for f in self.patterns],
            "breach": {
                "checked": self.hibp_checked,
                "count": self.breach_count,
                "status": self.breach_status,
            },
        }


def _decide_verdict(score: int, breach_count: int | None) -> tuple[str, str, str]:
    """Decide the overall verdict from the score and breach count.

    Returns ``(verdict, risk_band, summary_sentence)``.

    The breach check is applied first and overrides everything: any confirmed
    breach hit yields :data:`VERDICT_UNSAFE`. Only when the password is not
    breached does the ``zxcvbn`` score drive the verdict.
    """
    if breach_count is not None and breach_count > 0:
        return (
            VERDICT_UNSAFE,
            RISK_DANGER,
            "This password appears in real-world breach data. Treat it as "
            "already compromised and never use it anywhere — strength is "
            "irrelevant once a password is public.",
        )

    if score >= 3:
        return (
            VERDICT_SAFE,
            RISK_SAFE,
            "Strong password with no breach match. Pair it with a password "
            "manager and unique-per-site usage.",
        )
    if score == 2:
        return (
            VERDICT_WEAK,
            RISK_WARN,
            "Only fair strength. It would resist casual guessing but not a "
            "determined offline attack — make it longer and less predictable.",
        )
    return (
        VERDICT_WEAK,
        RISK_DANGER,
        "Weak password. It is fast to guess; choose a longer passphrase of "
        "several unrelated words.",
    )


def audit(password: str, *, check_breaches: bool = True) -> AuditReport:
    """Audit *password* and return a complete :class:`AuditReport`.

    Args:
        password: The password to evaluate. It is analysed in memory only and is
            never stored on the returned report, logged, or written to disk.
        check_breaches: When ``True`` (default) the password is checked against
            Have I Been Pwned using the k-anonymity model (only a 5-character
            hash prefix is transmitted). Set ``False`` for a fully offline audit.

    Returns:
        An :class:`AuditReport`. Note the overriding rule: if the breach check
        confirms a hit, the verdict is ``UNSAFE`` no matter how high the
        strength score is.
    """
    strength = analyze_strength(password)
    patterns = find_patterns(password)

    breach_count: int | None = None
    if check_breaches:
        breach_count = check_password(password)

    verdict, risk, summary = _decide_verdict(strength.score, breach_count)

    return AuditReport(
        score=strength.score,
        score_label=strength.zxcvbn.score_label,
        verdict=verdict,
        risk=risk,
        summary=summary,
        strength=strength,
        patterns=patterns,
        breach_count=breach_count,
        hibp_checked=check_breaches,
    )
