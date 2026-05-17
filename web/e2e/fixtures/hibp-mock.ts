/**
 * Deterministic HIBP range-API responses for Playwright route interception.
 *
 * The e2e suite never touches the real `api.pwnedpasswords.com`; it intercepts
 * the request and returns one of these fixed bodies, keyed by the 5-character
 * SHA-1 prefix the page sends. This keeps the tests offline and stable.
 */

/**
 * Map of `prefix -> range-API response body`.
 *
 * - `5BAA6` is the prefix of SHA-1("password"); the matching suffix is given a
 *   large count so the page must report the password as breached.
 * - Any prefix not in this map is treated as "not breached" (see
 *   {@link defaultRangeBody}).
 */
export const BREACHED_RANGE_BODIES: Readonly<Record<string, string>> = {
  // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
  '5BAA6':
    '0018A45C4D1DEF81644B54AB7F969B88D65:3\n' +
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n' +
    '00D4F6E8FA6EECAD2A3AA415EEC418D38EC:1\n',
}

/**
 * A response body containing only non-matching rows — used for any prefix that
 * is not in {@link BREACHED_RANGE_BODIES}, so the page reports "not breached".
 */
export const defaultRangeBody =
  '0018A45C4D1DEF81644B54AB7F969B88D65:5\n' +
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2\n' +
  '0000000000000000000000000000000000A:0\n'

/** Resolve the mock response body for a given 5-character prefix. */
export function rangeBodyForPrefix(prefix: string): string {
  return BREACHED_RANGE_BODIES[prefix.toUpperCase()] ?? defaultRangeBody
}
