/**
 * Unit tests for the browser-side transparent pattern detectors.
 */

import { describe, expect, it } from 'vitest'
import { findPatterns } from './patterns'

/** Return the set of finding codes raised for `password`. */
function codes(password: string): Set<string> {
  return new Set(findPatterns(password).map((f) => f.code))
}

describe('findPatterns', () => {
  it('detects a common password', () => {
    expect(codes('password')).toContain('common_password')
  })

  it('detects a sequential run', () => {
    expect(codes('abcd')).toContain('sequential')
    expect(codes('zz1234zz')).toContain('sequential')
  })

  it('detects a repeated-character run', () => {
    expect(codes('aaaa')).toContain('repeat')
  })

  it('detects a keyboard walk', () => {
    expect(codes('qwerty')).toContain('keyboard_walk')
    expect(codes('asdf')).toContain('keyboard_walk')
  })

  it('detects leetspeak of a common password', () => {
    expect(codes('p@ssw0rd')).toContain('leetspeak')
  })

  it('detects a 4-digit year', () => {
    expect(codes('summer2021')).toContain('year')
  })

  it('returns no findings for an empty password', () => {
    expect(findPatterns('')).toEqual([])
  })

  it('returns no findings for a strong random password', () => {
    expect(findPatterns('k4Lm9Qx2Vt7Zp1Rb6Wn')).toEqual([])
  })

  it('detects multiple patterns at once', () => {
    const c = codes('qwerty1234')
    expect(c).toContain('keyboard_walk')
    expect(c).toContain('sequential')
  })

  it('attaches a human-readable reason to every finding', () => {
    const findings = findPatterns('aaaa')
    expect(findings.length).toBeGreaterThan(0)
    for (const finding of findings) {
      expect(finding.reason.length).toBeGreaterThan(10)
    }
  })
})
