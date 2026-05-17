"""Tests for the combined strength analysis (naive entropy + zxcvbn)."""

from __future__ import annotations

import math

from pwaudit.strength import SCORE_LABELS, analyze_strength


class TestScoreOrdering:
    """The headline requirement: weaker passwords score no higher than stronger
    ones, using the realistic zxcvbn score."""

    def test_password_lt_passphrase_lt_random(self) -> None:
        weak = analyze_strength("password")
        passphrase = analyze_strength("correct horse battery staple")
        random20 = analyze_strength("k4Lm9Qx2Vt7Zp1Rb6Wn")

        # Strictly increasing realistic strength.
        assert weak.score < passphrase.score
        assert passphrase.score <= random20.score
        # And the extremes are clearly separated.
        assert weak.score <= 1
        assert random20.score == 4

    def test_zxcvbn_guesses_increase_with_strength(self) -> None:
        weak = analyze_strength("password")
        random20 = analyze_strength("k4Lm9Qx2Vt7Zp1Rb6Wn")
        assert random20.zxcvbn.guesses > weak.zxcvbn.guesses


class TestNaiveVsZxcvbn:
    """Both estimates are reported, and the naive model overestimates."""

    def test_both_estimates_present(self) -> None:
        result = analyze_strength("Password123!")
        # Naive charset entropy is computed.
        assert result.naive_entropy_bits > 0
        # zxcvbn estimate is present with crack-time strings.
        assert result.zxcvbn.crack_times_display
        assert 0 <= result.zxcvbn.score <= 4

    def test_naive_model_overestimates_a_predictable_password(self) -> None:
        # "Password123!" looks rich (all 4 classes, 12 chars) so naive entropy
        # is high, yet zxcvbn knows it is weak. This is exactly why the README
        # tells users to trust zxcvbn, not the charset entropy.
        result = analyze_strength("Password123!")
        # Naive entropy treats it as ~70+ bits of "randomness".
        assert result.naive_entropy_bits > 70
        # But zxcvbn rates it poorly.
        assert result.zxcvbn.score <= 2

    def test_score_property_matches_zxcvbn(self) -> None:
        result = analyze_strength("hello")
        assert result.score == result.zxcvbn.score


class TestZxcvbnFeedback:
    """zxcvbn feedback (warning + suggestions) is surfaced."""

    def test_weak_password_has_feedback(self) -> None:
        result = analyze_strength("password")
        # A very common password should produce a warning or suggestions.
        assert result.zxcvbn.warning or result.zxcvbn.suggestions

    def test_score_label_is_human_readable(self) -> None:
        result = analyze_strength("password")
        assert result.zxcvbn.score_label == SCORE_LABELS[result.zxcvbn.score]

    def test_crack_times_cover_all_scenarios(self) -> None:
        result = analyze_strength("correct horse battery staple")
        assert set(result.zxcvbn.crack_times_display) == {
            "online_throttled",
            "online_unthrottled",
            "offline_slow_hash",
            "offline_fast_hash",
        }


class TestCharsetIntegration:
    """The charset analysis is carried inside the strength result."""

    def test_charset_reflects_password(self) -> None:
        result = analyze_strength("Ab1!Ab1!")
        assert result.charset.classes_used == 4
        assert result.charset.length == 8

    def test_guesses_log10_is_finite(self) -> None:
        result = analyze_strength("k4Lm9Qx2Vt7Zp1Rb6Wn")
        assert math.isfinite(result.zxcvbn.guesses_log10)
        assert result.zxcvbn.guesses_log10 > 0
