"""Privacy-preserving breach lookup via the Have I Been Pwned range API.

How the k-anonymity model protects the password
------------------------------------------------
A naive breach check would send the password (or its full hash) to a server —
unacceptable. HIBP's *range* endpoint avoids that entirely:

1. Compute ``SHA-1(password)`` **locally** and uppercase the hex digest.
2. Split it into a 5-character **prefix** and a 35-character **suffix**.
3. Send **only the prefix** to ``GET /range/{prefix}``. Hundreds of hashes share
   any given prefix, so the server cannot tell which one you asked about.
4. The server returns every known suffix under that prefix, with a breach count.
5. Match the suffix **locally**. The password and its full hash never leave the
   machine, and the network sees only the 5-character prefix.

This module enforces that guarantee: :func:`_request_range` asserts the
constructed URL contains only the 5-character prefix before any request is made.
"""

from __future__ import annotations

import hashlib

import requests

# The HIBP Pwned Passwords range endpoint. No API key required; CORS-enabled.
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

# Identify this client politely, as the HIBP API guidance requests.
USER_AGENT = "pwaudit-password-strength-auditor (https://github.com/Sarthakagrwal)"

# Network timeout (connect, read) in seconds — keep the audit responsive.
REQUEST_TIMEOUT = 8.0


def sha1_hex(password: str) -> str:
    """Return the uppercase hex SHA-1 digest of *password*.

    SHA-1 is used **only** because the HIBP Pwned Passwords corpus is indexed by
    SHA-1; it is not used as a password-storage hash here. The digest is computed
    locally and only its first 5 characters are ever transmitted.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(sha1_upper: str) -> tuple[str, str]:
    """Split a 40-char uppercase SHA-1 digest into ``(prefix, suffix)``.

    The prefix is the first 5 characters (sent to the API); the suffix is the
    remaining 35 (matched locally).
    """
    if len(sha1_upper) != 40:
        raise ValueError("Expected a 40-character SHA-1 hex digest")
    return sha1_upper[:5], sha1_upper[5:]


def parse_range_response(body: str, wanted_suffix: str) -> int:
    """Parse a range-API response body and return the breach count.

    Each non-empty line has the form ``SUFFIX:COUNT``. Lines whose count is 0
    are *padding* (added when the request asks for ``Add-Padding: true``) and are
    ignored. If *wanted_suffix* is present with a non-zero count, that count is
    returned; otherwise the password was not found and ``0`` is returned.
    """
    wanted = wanted_suffix.upper()
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count_str = line.partition(":")
        try:
            count = int(count_str.strip())
        except ValueError:
            continue
        # Padding lines (count == 0) carry no information — skip them.
        if count == 0:
            continue
        if suffix.strip().upper() == wanted:
            return count
    return 0


def _request_range(prefix: str) -> str:
    """Fetch the raw range-API response body for a 5-character *prefix*.

    Asserts, before issuing the request, that the URL contains nothing beyond
    the 5-character prefix — a hard guarantee that the password and its full
    hash are never transmitted. The ``Add-Padding`` header asks HIBP to pad the
    response with decoy rows so its size cannot leak information.
    """
    if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
        raise ValueError("HIBP prefix must be exactly 5 uppercase hex characters")

    url = f"{HIBP_RANGE_URL}{prefix}"

    # Privacy assertion: the request URL must expose ONLY the 5-char prefix.
    assert url == HIBP_RANGE_URL + prefix, "URL must contain only the 5-char prefix"
    assert len(url) == len(HIBP_RANGE_URL) + 5, "URL carries more than the prefix"

    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.text


def check_password(password: str) -> int | None:
    """Check *password* against the HIBP breach corpus, privately.

    Returns:
        * a positive ``int`` — the number of times the password appears in known
          breaches;
        * ``0`` — the password was not found in any breach;
        * ``None`` — the HIBP service could not be reached (network error, DNS
          failure, timeout, HTTP error). The audit treats this as "breach status
          unavailable" and never crashes.

    Only the first 5 characters of ``SHA-1(password)`` are sent over the network.
    """
    full_hash = sha1_hex(password)
    prefix, suffix = split_hash(full_hash)
    try:
        body = _request_range(prefix)
    except (requests.RequestException, ValueError):
        # Any network/HTTP problem -> graceful "unavailable" rather than a crash.
        return None
    return parse_range_response(body, suffix)
