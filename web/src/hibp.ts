/**
 * Privacy-preserving breach lookup via the Have I Been Pwned range API.
 *
 * The k-anonymity model — why the password never leaves the browser:
 *  1. Compute `SHA-1(password)` locally with the Web Crypto API.
 *  2. Split the uppercase hex digest into a 5-char prefix + 35-char suffix.
 *  3. Send ONLY the prefix to `GET /range/{prefix}`. Hundreds of unrelated
 *     hashes share any prefix, so the server cannot tell which one was queried.
 *  4. Match the suffix locally against the returned list.
 *
 * The password and its full SHA-1 hash are never transmitted — only the
 * 5-character prefix appears in the network request.
 */

/** The HIBP Pwned Passwords range endpoint (no API key, CORS-enabled). */
export const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/'

/** Outcome of a breach check. */
export interface BreachResult {
  /** Times the password appears in known breaches; 0 if not found. */
  count: number
  /** True only when `count > 0`. */
  breached: boolean
}

/**
 * Compute the uppercase hex SHA-1 digest of `password` using Web Crypto.
 *
 * SHA-1 is used only because the HIBP corpus is indexed by SHA-1; it is not a
 * password-storage choice. The digest is computed entirely in-browser and only
 * its first 5 characters are ever sent over the network.
 */
export async function sha1Hex(password: string): Promise<string> {
  const data = new TextEncoder().encode(password)
  const digest = await crypto.subtle.digest('SHA-1', data)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

/**
 * Split a 40-character uppercase SHA-1 digest into `[prefix, suffix]`.
 *
 * The prefix (first 5 chars) is sent to the API; the suffix (remaining 35) is
 * matched locally. Throws if `sha1Upper` is not exactly 40 characters.
 */
export function splitHash(sha1Upper: string): [string, string] {
  if (sha1Upper.length !== 40) {
    throw new Error('Expected a 40-character SHA-1 hex digest')
  }
  return [sha1Upper.slice(0, 5), sha1Upper.slice(5)]
}

/**
 * Parse a range-API response body and return the breach count for a suffix.
 *
 * Each non-empty line is `SUFFIX:COUNT`. Lines with a count of 0 are padding
 * (added in response to the `Add-Padding` request header) and are ignored. If
 * `wantedSuffix` is present with a non-zero count that count is returned;
 * otherwise the password was not found and 0 is returned.
 */
export function parseRangeResponse(body: string, wantedSuffix: string): number {
  const wanted = wantedSuffix.toUpperCase()
  for (const rawLine of body.split('\n')) {
    const line = rawLine.trim()
    if (!line || !line.includes(':')) continue
    const idx = line.indexOf(':')
    const suffix = line.slice(0, idx).trim().toUpperCase()
    const count = Number.parseInt(line.slice(idx + 1).trim(), 10)
    if (!Number.isFinite(count) || count === 0) {
      // Either a malformed line or a padding row — carries no information.
      continue
    }
    if (suffix === wanted) {
      return count
    }
  }
  return 0
}

/**
 * Build the range-API request URL for a 5-character hex `prefix`.
 *
 * Throws if `prefix` is not exactly 5 uppercase hex characters. The returned
 * URL provably contains nothing beyond the prefix — the guarantee that the
 * password and its full hash are never transmitted.
 */
export function buildRangeUrl(prefix: string): string {
  if (!/^[0-9A-F]{5}$/.test(prefix)) {
    throw new Error('HIBP prefix must be exactly 5 uppercase hex characters')
  }
  const url = HIBP_RANGE_URL + prefix
  // Privacy assertion: the URL must expose ONLY the 5-character prefix.
  if (url !== HIBP_RANGE_URL + prefix || url.length !== HIBP_RANGE_URL.length + 5) {
    throw new Error('URL must contain only the 5-character prefix')
  }
  return url
}

/** Raised when the HIBP service cannot be reached. */
export class HibpUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'HibpUnavailableError'
  }
}

/**
 * Check `password` against the HIBP breach corpus, privately.
 *
 * Resolves to a {@link BreachResult}. Rejects with {@link HibpUnavailableError}
 * if the service is unreachable (network error, HTTP error) so callers can show
 * an "unavailable" state rather than a misleading "safe".
 *
 * Only the first 5 characters of `SHA-1(password)` are sent over the network.
 * The optional `fetchFn` parameter exists purely so tests can inject a mock.
 */
export async function checkPassword(
  password: string,
  fetchFn: typeof fetch = fetch,
): Promise<BreachResult> {
  const fullHash = await sha1Hex(password)
  const [prefix, suffix] = splitHash(fullHash)
  const url = buildRangeUrl(prefix)

  let response: Response
  try {
    response = await fetchFn(url, {
      headers: {
        // Ask HIBP to pad the response so its size cannot leak the prefix.
        'Add-Padding': 'true',
      },
    })
  } catch (err) {
    throw new HibpUnavailableError(
      `Could not reach Have I Been Pwned: ${(err as Error).message}`,
    )
  }

  if (!response.ok) {
    throw new HibpUnavailableError(
      `Have I Been Pwned returned HTTP ${response.status}`,
    )
  }

  const body = await response.text()
  const count = parseRangeResponse(body, suffix)
  return { count, breached: count > 0 }
}
