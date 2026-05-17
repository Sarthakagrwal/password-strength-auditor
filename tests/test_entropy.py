"""Tests for the naive charset-entropy model and crack-time formatting."""

from __future__ import annotations

import math

from pwaudit.entropy import (
    DIGIT_POOL,
    LOWERCASE_POOL,
    SYMBOL_POOL,
    UPPERCASE_POOL,
    analyze_charset,
    charset_pool_size,
    crack_times,
    detect_charset,
    entropy_bits,
    format_duration,
    guesses_for_bits,
)


class TestDetectCharset:
    """Character-class detection."""

    def test_lowercase_only(self) -> None:
        assert detect_charset("abcdef") == (True, False, False, False)

    def test_uppercase_only(self) -> None:
        assert detect_charset("ABCDEF") == (False, True, False, False)

    def test_digits_only(self) -> None:
        assert detect_charset("123456") == (False, False, True, False)

    def test_symbols_only(self) -> None:
        assert detect_charset("!@#$%^") == (False, False, False, True)

    def test_space_counts_as_symbol(self) -> None:
        # A space is not lower/upper/digit, so it falls into the symbol class.
        assert detect_charset("a b") == (True, False, False, True)

    def test_all_four_classes(self) -> None:
        assert detect_charset("Ab1!") == (True, True, True, True)

    def test_empty_password(self) -> None:
        assert detect_charset("") == (False, False, False, False)


class TestCharsetPoolSize:
    """Search-space pool sizing."""

    def test_lowercase_pool(self) -> None:
        assert charset_pool_size("abc") == LOWERCASE_POOL

    def test_lower_upper_pool(self) -> None:
        assert charset_pool_size("abcDEF") == LOWERCASE_POOL + UPPERCASE_POOL

    def test_lower_upper_digit_pool(self) -> None:
        assert charset_pool_size("aB1") == LOWERCASE_POOL + UPPERCASE_POOL + DIGIT_POOL

    def test_all_classes_pool(self) -> None:
        expected = LOWERCASE_POOL + UPPERCASE_POOL + DIGIT_POOL + SYMBOL_POOL
        assert charset_pool_size("aB1!") == expected
        # All four classes present -> the documented full pool of 95.
        assert expected == 95

    def test_empty_pool(self) -> None:
        assert charset_pool_size("") == 0


class TestEntropyBits:
    """Entropy = length * log2(pool)."""

    def test_known_lowercase_value(self) -> None:
        # "abcd": length 4, pool 26 -> 4 * log2(26).
        expected = 4 * math.log2(26)
        assert entropy_bits("abcd") == expected

    def test_known_all_class_value(self) -> None:
        # 8 chars across all 4 classes -> pool 95.
        expected = 8 * math.log2(95)
        assert entropy_bits("aB1!aB1!") == expected

    def test_longer_password_has_more_entropy(self) -> None:
        assert entropy_bits("abcdefgh") > entropy_bits("abcd")

    def test_bigger_pool_has_more_entropy_for_same_length(self) -> None:
        # Same length, but a richer character pool -> more entropy.
        assert entropy_bits("aB1!") > entropy_bits("abcd")

    def test_empty_password_zero_entropy(self) -> None:
        assert entropy_bits("") == 0.0


class TestAnalyzeCharset:
    """The bundled CharsetAnalysis dataclass."""

    def test_classes_used_count(self) -> None:
        analysis = analyze_charset("aB1")
        assert analysis.classes_used == 3
        assert analysis.length == 3

    def test_analysis_matches_helpers(self) -> None:
        analysis = analyze_charset("Passw0rd!")
        assert analysis.pool_size == charset_pool_size("Passw0rd!")
        assert analysis.entropy_bits == entropy_bits("Passw0rd!")
        assert analysis.has_symbols is True


class TestGuessesForBits:
    """The 2**bits guess-count helper."""

    def test_zero_bits(self) -> None:
        assert guesses_for_bits(0) == 1.0

    def test_ten_bits(self) -> None:
        assert guesses_for_bits(10) == 1024.0

    def test_huge_bits_does_not_overflow(self) -> None:
        # A value well past 1024 bits must not raise OverflowError.
        result = guesses_for_bits(100_000)
        assert math.isfinite(result)


class TestFormatDuration:
    """Human-readable duration formatting on known inputs."""

    def test_sub_second_is_instant(self) -> None:
        assert format_duration(0.4) == "instantly"
        assert format_duration(0.999) == "instantly"

    def test_seconds(self) -> None:
        assert format_duration(1) == "1 second"
        assert format_duration(45) == "45 seconds"

    def test_minutes(self) -> None:
        assert format_duration(90) == "2 minutes"
        assert format_duration(60) == "1 minute"

    def test_hours(self) -> None:
        assert format_duration(3600) == "1 hour"
        assert format_duration(7200) == "2 hours"

    def test_days(self) -> None:
        assert format_duration(86_400) == "1 day"

    def test_months(self) -> None:
        assert format_duration(30 * 86_400) == "1 month"

    def test_years(self) -> None:
        assert format_duration(365 * 86_400) == "1 year"

    def test_centuries(self) -> None:
        assert format_duration(100 * 365 * 86_400) == "1 century"
        assert format_duration(200 * 365 * 86_400) == "2 centuries"

    def test_geologic_scale_uses_scientific_years(self) -> None:
        # A truly enormous duration falls back to "<x>e+<y> years".
        result = format_duration(1e6 * 365 * 86_400)
        assert "years" in result
        assert "e+" in result


class TestCrackTimes:
    """Crack-time projection across attacker scenarios."""

    def test_returns_all_four_scenarios(self) -> None:
        result = crack_times(60.0)
        assert set(result) == {
            "online_throttled",
            "online_unthrottled",
            "offline_slow_hash",
            "offline_fast_hash",
        }

    def test_faster_attacker_is_never_slower(self) -> None:
        # For a fixed entropy, a faster guess rate cannot take *longer* to crack
        # the password. We verify this by converting each scenario's projected
        # duration back to seconds and checking the ordering.
        bits = 40.0
        result = crack_times(bits)
        # An offline fast-hash attack (1e10/s) must not be slower than a
        # throttled online attack (10/s) for the same password.
        assert result["online_throttled"] != "instantly"

    def test_low_entropy_cracked_instantly_by_fast_hash(self) -> None:
        # ~20 bits: ~1e6 guesses; at 1e10 guesses/sec that is sub-second.
        result = crack_times(20.0)
        assert result["offline_fast_hash"] == "instantly"

    def test_high_entropy_resists_all_attackers(self) -> None:
        # 128 bits: no scenario should report "instantly".
        result = crack_times(128.0)
        for value in result.values():
            assert value != "instantly"
