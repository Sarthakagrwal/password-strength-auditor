/**
 * Unit tests for the browser-side strength analysis (charset model + zxcvbn-ts).
 */

import { describe, expect, it } from 'vitest'
import {
  analyzeStrength,
  charsetPoolSize,
  countCharClasses,
  naiveEntropyBits,
  scoreToRiskBand,
} from './strength'

describe('charsetPoolSize', () => {
  it('sizes a lowercase-only pool', () => {
    expect(charsetPoolSize('abc')).toBe(26)
  })

  it('sizes a lower + upper + digit pool', () => {
    expect(charsetPoolSize('aB1')).toBe(26 + 26 + 10)
  })

  it('sizes the full pool with symbols', () => {
    // 26 + 26 + 10 + 33 = 95.
    expect(charsetPoolSize('aB1!')).toBe(95)
  })

  it('returns 0 for an empty password', () => {
    expect(charsetPoolSize('')).toBe(0)
  })
})

describe('countCharClasses', () => {
  it('counts each class once', () => {
    expect(countCharClasses('abc')).toBe(1)
    expect(countCharClasses('aB1!')).toBe(4)
  })
})

describe('naiveEntropyBits', () => {
  it('computes length * log2(pool)', () => {
    expect(naiveEntropyBits('abcd')).toBeCloseTo(4 * Math.log2(26))
  })

  it('grows with length', () => {
    expect(naiveEntropyBits('abcdefgh')).toBeGreaterThan(naiveEntropyBits('abcd'))
  })

  it('grows with a richer character pool', () => {
    expect(naiveEntropyBits('aB1!')).toBeGreaterThan(naiveEntropyBits('abcd'))
  })

  it('is 0 for an empty password', () => {
    expect(naiveEntropyBits('')).toBe(0)
  })
})

describe('scoreToRiskBand', () => {
  it('maps scores to the shared risk scale', () => {
    expect(scoreToRiskBand(0)).toBe('danger')
    expect(scoreToRiskBand(1)).toBe('danger')
    expect(scoreToRiskBand(2)).toBe('warn')
    expect(scoreToRiskBand(3)).toBe('safe')
    expect(scoreToRiskBand(4)).toBe('safe')
  })
})

describe('analyzeStrength — zxcvbn integration', () => {
  it('orders password < passphrase < random by realistic score', () => {
    const weak = analyzeStrength('password')
    const passphrase = analyzeStrength('correct horse battery staple')
    const random20 = analyzeStrength('k4Lm9Qx2Vt7Zp1Rb6Wn')

    expect(weak.score).toBeLessThan(passphrase.score)
    expect(passphrase.score).toBeLessThanOrEqual(random20.score)
    expect(weak.score).toBeLessThanOrEqual(1)
    expect(random20.score).toBe(4)
  })

  it('reports both the naive and zxcvbn estimates', () => {
    const result = analyzeStrength('Password123!')
    expect(result.naiveEntropyBits).toBeGreaterThan(0)
    expect(result.guessesLog10).toBeGreaterThan(0)
  })

  it('shows the naive model overestimating a predictable password', () => {
    // "Password123!" has 4 classes and 12 chars, so naive entropy is high...
    const result = analyzeStrength('Password123!')
    expect(result.naiveEntropyBits).toBeGreaterThan(70)
    // ...yet zxcvbn rates it weak.
    expect(result.score).toBeLessThanOrEqual(2)
  })

  it('provides crack times for all four scenarios', () => {
    const result = analyzeStrength('hunter2')
    expect(result.crackTimes.onlineThrottled).toBeTruthy()
    expect(result.crackTimes.onlineUnthrottled).toBeTruthy()
    expect(result.crackTimes.offlineSlowHash).toBeTruthy()
    expect(result.crackTimes.offlineFastHash).toBeTruthy()
  })

  it('surfaces zxcvbn feedback for a weak password', () => {
    const result = analyzeStrength('password')
    expect(result.warning.length + result.suggestions.length).toBeGreaterThan(0)
  })

  it('assigns a human-readable score label and risk band', () => {
    const result = analyzeStrength('k4Lm9Qx2Vt7Zp1Rb6Wn')
    expect(result.scoreLabel).toBe('Very strong')
    expect(result.riskBand).toBe('safe')
  })
})
