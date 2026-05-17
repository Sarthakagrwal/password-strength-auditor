/**
 * Unit tests for the browser-side HIBP k-anonymity client.
 *
 * `fetch` is mocked throughout so the suite is deterministic and offline. The
 * crafted range-API responses come from `__fixtures__/hibp_cases.json`. The most
 * important assertions verify the privacy guarantee: only the 5-character SHA-1
 * prefix is ever sent over the network.
 */

import { describe, expect, it, vi } from 'vitest'
import {
  HIBP_RANGE_URL,
  HibpUnavailableError,
  buildRangeUrl,
  checkPassword,
  parseRangeResponse,
  sha1Hex,
  splitHash,
} from './hibp'
import hibpCases from './__fixtures__/hibp_cases.json'

interface HibpCase {
  name: string
  password: string
  prefix: string
  suffix: string
  responseBody: string
  expectedCount: number
  expectedBreached: boolean
}

const CASES = hibpCases.cases as HibpCase[]

/** Build a mock `fetch` that returns `body` with HTTP 200. */
function mockFetchOk(body: string): typeof fetch {
  return vi.fn(
    async () => new Response(body, { status: 200 }),
  ) as unknown as typeof fetch
}

describe('sha1Hex', () => {
  it('produces the known SHA-1 of "password"', async () => {
    const digest = await sha1Hex('password')
    expect(digest).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8')
  })

  it('returns an uppercase 40-character hex string', async () => {
    const digest = await sha1Hex('anything at all')
    expect(digest).toHaveLength(40)
    expect(digest).toBe(digest.toUpperCase())
    expect(digest).toMatch(/^[0-9A-F]{40}$/)
  })

  it('is deterministic for the same input', async () => {
    expect(await sha1Hex('repeat')).toBe(await sha1Hex('repeat'))
  })
})

describe('splitHash', () => {
  it('splits into a 5-char prefix and 35-char suffix', () => {
    const [prefix, suffix] = splitHash('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8')
    expect(prefix).toBe('5BAA6')
    expect(suffix).toBe('1E4C9B93F3F0682250B6CF8331B7EE68FD8')
    expect(prefix).toHaveLength(5)
    expect(suffix).toHaveLength(35)
  })

  it('throws on a digest of the wrong length', () => {
    expect(() => splitHash('TOOSHORT')).toThrow()
  })
})

describe('buildRangeUrl', () => {
  it('appends only the 5-character prefix to the range endpoint', () => {
    expect(buildRangeUrl('5BAA6')).toBe(`${HIBP_RANGE_URL}5BAA6`)
  })

  it('rejects a prefix that is not 5 uppercase hex characters', () => {
    expect(() => buildRangeUrl('5baa6')).toThrow() // lowercase
    expect(() => buildRangeUrl('5BAA')).toThrow() // too short
    expect(() => buildRangeUrl('5BAA61')).toThrow() // too long
    expect(() => buildRangeUrl('5BAAG')).toThrow() // non-hex
  })
})

describe('parseRangeResponse', () => {
  it('returns the count for a present suffix', () => {
    const body = 'ABCDEF0000000000000000000000000000000:5\nDEADBEEF000000000000000000000000000:99\n'
    expect(parseRangeResponse(body, 'DEADBEEF000000000000000000000000000')).toBe(99)
  })

  it('returns 0 when the suffix is absent', () => {
    const body = 'ABCDEF0000000000000000000000000000000:5\n'
    expect(parseRangeResponse(body, 'DEADBEEF000000000000000000000000000')).toBe(0)
  })

  it('ignores padding lines whose count is 0', () => {
    const body = 'DEADBEEF000000000000000000000000000:0\nABCDEF0000000000000000000000000000000:7\n'
    expect(parseRangeResponse(body, 'DEADBEEF000000000000000000000000000')).toBe(0)
  })

  it('matches suffixes case-insensitively', () => {
    const body = 'deadbeef000000000000000000000000000:13\n'
    expect(parseRangeResponse(body, 'DEADBEEF000000000000000000000000000')).toBe(13)
  })

  it('skips malformed lines', () => {
    const body = 'no-colon-here\n:\nDEADBEEF000000000000000000000000000:21\nXYZ:notanumber\n'
    expect(parseRangeResponse(body, 'DEADBEEF000000000000000000000000000')).toBe(21)
  })

  it('returns 0 for an empty body', () => {
    expect(parseRangeResponse('', 'DEADBEEF000000000000000000000000000')).toBe(0)
  })
})

describe('checkPassword — fixture-driven', () => {
  for (const testCase of CASES) {
    it(testCase.name, async () => {
      const fetchMock = mockFetchOk(testCase.responseBody)
      const result = await checkPassword(testCase.password, fetchMock)
      expect(result.count).toBe(testCase.expectedCount)
      expect(result.breached).toBe(testCase.expectedBreached)
    })
  }
})

describe('checkPassword — privacy guarantee', () => {
  it('sends only the 5-character prefix in the request URL', async () => {
    const fetchMock = mockFetchOk('1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\n')
    await checkPassword('password', fetchMock)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const calledUrl = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][0] as string

    // The URL is exactly the range endpoint plus the 5-character prefix.
    expect(calledUrl).toBe(`${HIBP_RANGE_URL}5BAA6`)
    // The part appended by the client is ONLY the 5-char prefix.
    const appended = calledUrl.slice(HIBP_RANGE_URL.length)
    expect(appended).toBe('5BAA6')
    expect(appended).toHaveLength(5)
    // The full hash and the suffix must NOT appear in the URL.
    expect(calledUrl).not.toContain('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8')
    expect(calledUrl).not.toContain('1E4C9B93F3F0682250B6CF8331B7EE68FD8')
  })

  it('sends the Add-Padding request header', async () => {
    const fetchMock = mockFetchOk('1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\n')
    await checkPassword('password', fetchMock)

    const init = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['Add-Padding']).toBe('true')
  })

  it('makes exactly one network request', async () => {
    const fetchMock = mockFetchOk('1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\n')
    await checkPassword('password', fetchMock)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('checkPassword — failure handling', () => {
  it('rejects with HibpUnavailableError on a network failure', async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError('network down')
    }) as unknown as typeof fetch
    await expect(checkPassword('password', fetchMock)).rejects.toBeInstanceOf(
      HibpUnavailableError,
    )
  })

  it('rejects with HibpUnavailableError on an HTTP 500', async () => {
    const fetchMock = vi.fn(
      async () => new Response('Server Error', { status: 500 }),
    ) as unknown as typeof fetch
    await expect(checkPassword('password', fetchMock)).rejects.toBeInstanceOf(
      HibpUnavailableError,
    )
  })
})
