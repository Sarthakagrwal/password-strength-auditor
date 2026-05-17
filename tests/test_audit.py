"""Tests for the top-level audit orchestration.

These tests focus on the overriding rule: a password found in a breach is
reported UNSAFE regardless of how strong it is. The HIBP call is patched so the
suite is deterministic and offline.
"""

from __future__ import annotations

from unittest.mock import patch

from pwaudit.audit import (
    RISK_DANGER,
    RISK_SAFE,
    VERDICT_SAFE,
    VERDICT_UNSAFE,
    VERDICT_WEAK,
    audit,
)

# A genuinely strong, high-entropy password used to prove that breach presence
# overrides strength.
STRONG_PASSWORD = "k4Lm9Qx2Vt7Zp1Rb6Wn"


def _audit_with_breach_count(password: str, count: int | None):
    """Audit *password* with the HIBP call patched to return *count*."""
    with patch("pwaudit.audit.check_password", return_value=count) as mock:
        report = audit(password)
    return report, mock


class TestBreachOverridesStrength:
    """The headline rule: breached => UNSAFE, no matter the strength score."""

    def test_strong_but_breached_password_is_unsafe(self) -> None:
        # Pretend even our strong password turned up in a breach.
        report, _ = _audit_with_breach_count(STRONG_PASSWORD, 1)

        # The strength score is still high...
        assert report.score >= 3
        # ...but the verdict is UNSAFE because it is breached.
        assert report.verdict == VERDICT_UNSAFE
        assert report.risk == RISK_DANGER
        assert report.breached is True

    def test_strong_unbreached_password_is_safe(self) -> None:
        report, _ = _audit_with_breach_count(STRONG_PASSWORD, 0)
        assert report.verdict == VERDICT_SAFE
        assert report.risk == RISK_SAFE
        assert report.breached is False

    def test_breach_summary_mentions_compromise(self) -> None:
        report, _ = _audit_with_breach_count(STRONG_PASSWORD, 500)
        # The summary should make clear the password is compromised.
        assert "breach" in report.summary.lower()
        assert report.breach_count == 500


class TestWeakPasswordVerdicts:
    """Verdicts for non-breached passwords are driven by the zxcvbn score."""

    def test_weak_unbreached_password_is_weak(self) -> None:
        report, _ = _audit_with_breach_count("hunter2", 0)
        assert report.verdict == VERDICT_WEAK
        assert report.score <= 2

    def test_weak_and_breached_password_is_unsafe(self) -> None:
        report, _ = _audit_with_breach_count("password", 99999)
        assert report.verdict == VERDICT_UNSAFE
        assert report.breached is True


class TestHibpUnavailable:
    """When HIBP cannot be reached the audit degrades gracefully."""

    def test_unavailable_breach_check_does_not_crash(self) -> None:
        # check_password returns None on a network failure.
        report, _ = _audit_with_breach_count(STRONG_PASSWORD, None)
        assert report.breach_count is None
        assert report.breached is False
        # With breach status unknown, the verdict falls back to the strength
        # score — a strong password is still SAFE.
        assert report.verdict == VERDICT_SAFE
        assert "Unavailable" in report.breach_status

    def test_unavailable_does_not_mask_a_weak_password(self) -> None:
        report, _ = _audit_with_breach_count("hunter2", None)
        assert report.verdict == VERDICT_WEAK


class TestOfflineMode:
    """``check_breaches=False`` skips the HIBP call entirely."""

    def test_offline_mode_skips_hibp_call(self) -> None:
        with patch("pwaudit.audit.check_password") as mock:
            report = audit(STRONG_PASSWORD, check_breaches=False)
        mock.assert_not_called()
        assert report.hibp_checked is False
        assert report.breach_count is None
        assert "offline" in report.breach_status.lower()

    def test_offline_strong_password_is_safe(self) -> None:
        report = audit(STRONG_PASSWORD, check_breaches=False)
        assert report.verdict == VERDICT_SAFE


class TestReportContents:
    """The report carries the expected analysis and never the password."""

    def test_report_includes_patterns(self) -> None:
        report, _ = _audit_with_breach_count("qwerty1234", 0)
        codes = {f.code for f in report.patterns}
        assert "keyboard_walk" in codes

    def test_report_includes_both_entropy_estimates(self) -> None:
        report, _ = _audit_with_breach_count(STRONG_PASSWORD, 0)
        assert report.strength.naive_entropy_bits > 0
        assert report.strength.zxcvbn.crack_times_display

    def test_to_dict_is_json_safe_and_has_no_password(self) -> None:
        import json

        report, _ = _audit_with_breach_count("Password123!", 7)
        payload = report.to_dict()
        # Must serialise cleanly to JSON.
        serialised = json.dumps(payload)
        # The password must not appear anywhere in the serialised report.
        assert "Password123!" not in serialised
        # Core fields are present.
        assert payload["verdict"] == VERDICT_UNSAFE
        assert payload["breach"]["count"] == 7

    def test_breach_count_pluralisation(self) -> None:
        single, _ = _audit_with_breach_count(STRONG_PASSWORD, 1)
        assert "1 time" in single.breach_status
        multi, _ = _audit_with_breach_count(STRONG_PASSWORD, 5)
        assert "5 times" in multi.breach_status
