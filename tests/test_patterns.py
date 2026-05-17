"""Tests for the transparent pattern detectors."""

from __future__ import annotations

from pwaudit.patterns import find_patterns


def _codes(password: str) -> set[str]:
    """Return the set of finding codes raised for *password*."""
    return {f.code for f in find_patterns(password)}


class TestCommonPassword:
    """Bundled common-password dictionary detection."""

    def test_plain_common_password_detected(self) -> None:
        assert "common_password" in _codes("password")

    def test_common_password_case_insensitive(self) -> None:
        assert "common_password" in _codes("PASSWORD")
        assert "common_password" in _codes("Password")

    def test_uncommon_password_not_flagged(self) -> None:
        # A random-looking string is not in the bundled list.
        assert "common_password" not in _codes("Xq7#mLp2vR8wZt")


class TestSequentialRuns:
    """Ascending / descending character runs."""

    def test_ascending_letters(self) -> None:
        assert "sequential" in _codes("abcdef")

    def test_ascending_digits(self) -> None:
        assert "sequential" in _codes("1234")

    def test_descending_digits(self) -> None:
        assert "sequential" in _codes("4321")

    def test_sequence_embedded_in_password(self) -> None:
        assert "sequential" in _codes("zz1234zz")

    def test_no_sequence_in_random_string(self) -> None:
        assert "sequential" not in _codes("a7g2k9")

    def test_short_run_not_flagged(self) -> None:
        # Only 3 consecutive chars — below the 4-char threshold.
        assert "sequential" not in _codes("abc")


class TestRepeatRuns:
    """Repeated-character runs."""

    def test_repeated_letter(self) -> None:
        assert "repeat" in _codes("aaaa")

    def test_repeated_digit(self) -> None:
        assert "repeat" in _codes("0000")

    def test_repeat_embedded(self) -> None:
        assert "repeat" in _codes("xyzzzzxy")

    def test_short_repeat_not_flagged(self) -> None:
        # Only 3 in a row — below the threshold.
        assert "repeat" not in _codes("aaa")

    def test_no_repeat_in_varied_string(self) -> None:
        assert "repeat" not in _codes("ababab")


class TestKeyboardWalks:
    """QWERTY keyboard-row walk detection."""

    def test_qwerty_walk(self) -> None:
        assert "keyboard_walk" in _codes("qwerty")

    def test_asdf_walk(self) -> None:
        assert "keyboard_walk" in _codes("asdf")

    def test_reverse_walk(self) -> None:
        # A backwards walk along a row should also be caught.
        assert "keyboard_walk" in _codes("rewq")

    def test_walk_embedded(self) -> None:
        assert "keyboard_walk" in _codes("99asdf99")

    def test_no_walk_in_random_string(self) -> None:
        assert "keyboard_walk" not in _codes("m3x8q1z5")


class TestLeetspeak:
    """Leetspeak obfuscation of common passwords."""

    def test_leet_password_detected(self) -> None:
        # p@ssw0rd de-leets to "password", a common password.
        assert "leetspeak" in _codes("p@ssw0rd")

    def test_leet_passw0rd_variant(self) -> None:
        assert "leetspeak" in _codes("passw0rd")

    def test_plain_word_without_leet_not_flagged_as_leet(self) -> None:
        # "password" has no leet substitution, so the leet detector stays quiet
        # (it is still caught by the common-password detector).
        assert "leetspeak" not in _codes("password")

    def test_random_leetish_string_not_flagged(self) -> None:
        # Contains leet chars but does not de-leet to a known common password.
        assert "leetspeak" not in _codes("x9@7q1z3")


class TestYearPattern:
    """Four-digit year detection."""

    def test_1900s_year(self) -> None:
        assert "year" in _codes("john1987")

    def test_2000s_year(self) -> None:
        assert "year" in _codes("summer2021")

    def test_no_year_in_plain_digits(self) -> None:
        # 4321 is not a plausible 1900-2039 year.
        assert "year" not in _codes("ab4321cd")


class TestCombinedAndEdgeCases:
    """Multiple detectors firing together, and boundary inputs."""

    def test_empty_password_no_findings(self) -> None:
        assert find_patterns("") == []

    def test_multiple_patterns_detected_together(self) -> None:
        # "qwerty1234" is both a keyboard walk and a sequential run.
        codes = _codes("qwerty1234")
        assert "keyboard_walk" in codes
        assert "sequential" in codes

    def test_findings_carry_human_readable_reasons(self) -> None:
        findings = find_patterns("aaaa")
        assert findings, "expected at least one finding"
        for finding in findings:
            assert finding.reason
            assert len(finding.reason) > 10

    def test_strong_password_has_no_findings(self) -> None:
        assert find_patterns("Xq7#mLp2vR8wZt") == []
