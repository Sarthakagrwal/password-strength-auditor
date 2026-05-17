"""Tests for the privacy-preserving HIBP k-anonymity client.

Every test mocks ``api.pwnedpasswords.com`` with the ``responses`` library so the
suite is deterministic and offline. The most important assertions verify the
**privacy guarantee**: the request URL must contain only the 5-character SHA-1
prefix — never the password and never the full hash.
"""

from __future__ import annotations

import re

import pytest
import requests
import responses

from pwaudit.hibp import (
    HIBP_RANGE_URL,
    check_password,
    parse_range_response,
    sha1_hex,
    split_hash,
)

# "password" has a well-known, stable SHA-1 digest.
PASSWORD = "password"
FULL_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


class TestHashHelpers:
    """SHA-1 hashing and prefix/suffix splitting."""

    def test_sha1_hex_known_value(self) -> None:
        assert sha1_hex(PASSWORD) == FULL_HASH

    def test_sha1_hex_is_uppercase_40_chars(self) -> None:
        digest = sha1_hex("anything")
        assert len(digest) == 40
        assert digest == digest.upper()

    def test_split_hash(self) -> None:
        prefix, suffix = split_hash(FULL_HASH)
        assert prefix == PREFIX
        assert suffix == SUFFIX
        assert len(prefix) == 5
        assert len(suffix) == 35

    def test_split_hash_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError):
            split_hash("TOOSHORT")


class TestParseRangeResponse:
    """Parsing of the plain-text range-API body."""

    def test_known_suffix_returns_count(self) -> None:
        body = f"ABCDEF0000000000000000000000000000000:5\n{SUFFIX}:99\n"
        assert parse_range_response(body, SUFFIX) == 99

    def test_absent_suffix_returns_zero(self) -> None:
        body = "ABCDEF0000000000000000000000000000000:5\n"
        assert parse_range_response(body, SUFFIX) == 0

    def test_padding_lines_with_count_zero_are_ignored(self) -> None:
        # A padding line (count 0) that happens to carry our suffix must NOT be
        # mistaken for a real breach hit.
        body = (
            f"{SUFFIX}:0\n"  # padding row
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n"  # more padding
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:7\n"
        )
        assert parse_range_response(body, SUFFIX) == 0

    def test_suffix_match_is_case_insensitive(self) -> None:
        body = f"{SUFFIX.lower()}:42\n"
        assert parse_range_response(body, SUFFIX) == 42

    def test_malformed_lines_are_skipped(self) -> None:
        body = f"garbage-no-colon\n:\n{SUFFIX}:13\nXYZ:notanumber\n"
        assert parse_range_response(body, SUFFIX) == 13

    def test_empty_body_returns_zero(self) -> None:
        assert parse_range_response("", SUFFIX) == 0


class TestCheckPasswordMocked:
    """End-to-end ``check_password`` behaviour against a mocked API."""

    @responses.activate
    def test_breached_password_returns_count(self) -> None:
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=f"ABCDEF0000000000000000000000000000000:1\n{SUFFIX}:52256179\n",
            status=200,
            content_type="text/plain",
        )
        assert check_password(PASSWORD) == 52256179

    @responses.activate
    def test_unbreached_password_returns_zero(self) -> None:
        # Response lists other suffixes but not ours.
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body="ABCDEF0000000000000000000000000000000:3\n",
            status=200,
            content_type="text/plain",
        )
        assert check_password(PASSWORD) == 0

    @responses.activate
    def test_padding_only_response_returns_zero(self) -> None:
        # Server returns only padding (all counts 0) — treated as "not found".
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=f"{SUFFIX}:0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n",
            status=200,
            content_type="text/plain",
        )
        assert check_password(PASSWORD) == 0

    @responses.activate
    def test_network_error_returns_none_not_crash(self) -> None:
        # A connection failure must yield None, never an exception.
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=requests.ConnectionError("simulated network failure"),
        )
        assert check_password(PASSWORD) is None

    @responses.activate
    def test_http_500_returns_none_not_crash(self) -> None:
        # A server error is handled gracefully as "unavailable".
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body="Internal Server Error",
            status=500,
        )
        assert check_password(PASSWORD) is None

    @responses.activate
    def test_timeout_returns_none_not_crash(self) -> None:
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=requests.Timeout("simulated timeout"),
        )
        assert check_password(PASSWORD) is None


class TestPrivacyGuarantee:
    """The password and full hash must never appear in the network request."""

    @responses.activate
    def test_request_url_contains_only_the_prefix(self) -> None:
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=f"{SUFFIX}:5\n",
            status=200,
        )
        check_password(PASSWORD)

        assert len(responses.calls) == 1
        called_url = responses.calls[0].request.url

        # The URL is exactly the range endpoint plus the 5-character prefix.
        assert called_url == HIBP_RANGE_URL + PREFIX
        # The part of the URL the client appended is ONLY the 5-char prefix —
        # this is the core privacy guarantee.
        appended = called_url[len(HIBP_RANGE_URL) :]
        assert appended == PREFIX
        assert len(appended) == 5
        # The full hash must NOT appear anywhere in the URL.
        assert FULL_HASH not in called_url
        # The 35-character suffix (which, with the prefix, identifies the exact
        # password hash) must NOT appear anywhere in the URL.
        assert SUFFIX not in called_url

    @responses.activate
    def test_only_one_prefix_request_is_made(self) -> None:
        responses.add(
            responses.GET,
            re.compile(re.escape(HIBP_RANGE_URL) + r"[0-9A-F]{5}"),
            body=f"{SUFFIX}:9\n",
            status=200,
        )
        check_password(PASSWORD)
        # Exactly one request — to the range endpoint, prefix only.
        assert len(responses.calls) == 1

    @responses.activate
    def test_request_sends_padding_header(self) -> None:
        # The Add-Padding header is required so the response size cannot leak
        # which prefix was queried.
        responses.add(
            responses.GET,
            HIBP_RANGE_URL + PREFIX,
            body=f"{SUFFIX}:1\n",
            status=200,
        )
        check_password(PASSWORD)
        headers = responses.calls[0].request.headers
        assert headers.get("Add-Padding") == "true"
        assert "User-Agent" in headers
