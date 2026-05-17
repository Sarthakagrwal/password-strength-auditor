/**
 * Unit tests for crack-time duration and guess-count formatting.
 */

import { describe, expect, it } from 'vitest'
import { formatCrackTime, formatGuessesFromLog10 } from './crackTime'

const MINUTE = 60
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const MONTH = 30 * DAY
const YEAR = 365 * DAY
const CENTURY = 100 * YEAR

describe('formatCrackTime', () => {
  it('reports sub-second durations as "instantly"', () => {
    expect(formatCrackTime(0)).toBe('instantly')
    expect(formatCrackTime(0.4)).toBe('instantly')
    expect(formatCrackTime(0.999)).toBe('instantly')
  })

  it('formats seconds', () => {
    expect(formatCrackTime(1)).toBe('1 second')
    expect(formatCrackTime(45)).toBe('45 seconds')
  })

  it('formats minutes', () => {
    expect(formatCrackTime(MINUTE)).toBe('1 minute')
    expect(formatCrackTime(90)).toBe('2 minutes')
  })

  it('formats hours', () => {
    expect(formatCrackTime(HOUR)).toBe('1 hour')
    expect(formatCrackTime(2 * HOUR)).toBe('2 hours')
  })

  it('formats days', () => {
    expect(formatCrackTime(DAY)).toBe('1 day')
    expect(formatCrackTime(3 * DAY)).toBe('3 days')
  })

  it('formats months', () => {
    expect(formatCrackTime(MONTH)).toBe('1 month')
  })

  it('formats years', () => {
    expect(formatCrackTime(YEAR)).toBe('1 year')
    expect(formatCrackTime(5 * YEAR)).toBe('5 years')
  })

  it('formats centuries', () => {
    expect(formatCrackTime(CENTURY)).toBe('1 century')
    expect(formatCrackTime(3 * CENTURY)).toBe('3 centuries')
  })

  it('falls back to scientific-notation years for geologic timescales', () => {
    const result = formatCrackTime(1e7 * YEAR)
    expect(result).toContain('years')
    expect(result).toMatch(/e\+?\d/)
  })

  it('treats NaN / negative input as "instantly"', () => {
    expect(formatCrackTime(NaN)).toBe('instantly')
    expect(formatCrackTime(-100)).toBe('instantly')
  })

  it('picks the natural unit, not a fraction of a larger one', () => {
    // 90 seconds must read as minutes, never "0 centuries" or similar.
    expect(formatCrackTime(90)).toBe('2 minutes')
    // Two days is days, not "0 months".
    expect(formatCrackTime(2 * DAY)).toBe('2 days')
  })
})

describe('formatGuessesFromLog10', () => {
  it('shows small counts literally with thousands separators', () => {
    // log10(500) ~ 2.70 ; log10(12345) ~ 4.09 — both under the 10^5 threshold.
    expect(formatGuessesFromLog10(Math.log10(500))).toBe('500')
    expect(formatGuessesFromLog10(Math.log10(12345))).toBe('12,345')
  })

  it('shows large counts in 10^n form', () => {
    expect(formatGuessesFromLog10(9)).toBe('10^9.0')
    expect(formatGuessesFromLog10(14)).toBe('10^14.0')
  })

  it('does not overflow for an astronomically large search space', () => {
    // A 60-character random password has a guesses-log10 in the hundreds.
    expect(formatGuessesFromLog10(300)).toBe('10^300.0')
  })

  it('handles zero and invalid input', () => {
    expect(formatGuessesFromLog10(0)).toBe('1')
    expect(formatGuessesFromLog10(-5)).toBe('0')
    expect(formatGuessesFromLog10(NaN)).toBe('0')
  })
})
