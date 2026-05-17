/**
 * Password-strength analysis for the browser.
 *
 * Two estimates are produced for every password:
 *  - **Naive charset entropy** — `length * log2(pool)`, assuming the password is
 *    a uniformly random string. This *overestimates* real strength because
 *    human passwords are predictable.
 *  - **zxcvbn-ts estimate** — the realistic, dictionary/pattern-aware estimator.
 *    Its 0–4 `score` is the number the UI treats as trustworthy.
 *
 * The naive model is shown alongside zxcvbn precisely so a user can see the gap
 * between "looks random" and "is actually hard to guess".
 */

import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core'
import * as zxcvbnCommon from '@zxcvbn-ts/language-common'
import * as zxcvbnEn from '@zxcvbn-ts/language-en'
import { formatCrackTime } from './crackTime'

// --- Character-class pool sizes (must match the Python pwaudit.entropy) -------
const LOWERCASE_POOL = 26
const UPPERCASE_POOL = 26
const DIGIT_POOL = 10
// ASCII punctuation (32) + space = 33.
const SYMBOL_POOL = 33

/** Human-readable label for each zxcvbn 0–4 score. */
export const SCORE_LABELS: Readonly<Record<number, string>> = {
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
}

/** Risk band aligned with the shared green / amber / red scale. */
export type RiskBand = 'safe' | 'warn' | 'danger'

/** Crack-time projections (human-readable) across the four attacker scenarios. */
export interface CrackTimes {
  onlineThrottled: string
  onlineUnthrottled: string
  offlineSlowHash: string
  offlineFastHash: string
}

/** The complete strength analysis for one password. */
export interface StrengthResult {
  /** The trustworthy 0–4 score from zxcvbn-ts. */
  score: number
  scoreLabel: string
  riskBand: RiskBand
  /** Naive charset entropy in bits (optimistic). */
  naiveEntropyBits: number
  /** Combined character-pool size used by the naive model. */
  poolSize: number
  /** Number of distinct character classes present (0–4). */
  classesUsed: number
  /** Password length. */
  length: number
  /** zxcvbn guess count, as a base-10 logarithm. */
  guessesLog10: number
  /** Crack times from zxcvbn (the realistic figures shown in the UI). */
  crackTimes: CrackTimes
  /** zxcvbn's warning string (may be empty). */
  warning: string
  /** zxcvbn's improvement suggestions (may be empty). */
  suggestions: string[]
}

let optionsConfigured = false

/**
 * Configure zxcvbn-ts once with the common + English language packs.
 *
 * Idempotent: safe to call before every analysis; the setup runs only once.
 */
function ensureZxcvbnConfigured(): void {
  if (optionsConfigured) return
  zxcvbnOptions.setOptions({
    dictionary: {
      ...zxcvbnCommon.dictionary,
      ...zxcvbnEn.dictionary,
    },
    graphs: zxcvbnCommon.adjacencyGraphs,
    translations: zxcvbnEn.translations,
  })
  optionsConfigured = true
}

/** Return the combined charset pool size for `password`. */
export function charsetPoolSize(password: string): number {
  let pool = 0
  if (/[a-z]/.test(password)) pool += LOWERCASE_POOL
  if (/[A-Z]/.test(password)) pool += UPPERCASE_POOL
  if (/[0-9]/.test(password)) pool += DIGIT_POOL
  // Anything that is not an ASCII letter or digit counts toward "symbols".
  if (/[^a-zA-Z0-9]/.test(password)) pool += SYMBOL_POOL
  return pool
}

/** Count how many of the four character classes appear in `password`. */
export function countCharClasses(password: string): number {
  let n = 0
  if (/[a-z]/.test(password)) n++
  if (/[A-Z]/.test(password)) n++
  if (/[0-9]/.test(password)) n++
  if (/[^a-zA-Z0-9]/.test(password)) n++
  return n
}

/**
 * Naive charset entropy in bits: `length * log2(pool)`.
 *
 * Returns 0 for an empty password or a degenerate pool.
 */
export function naiveEntropyBits(password: string): number {
  const pool = charsetPoolSize(password)
  if (pool <= 1 || password.length === 0) return 0
  return password.length * Math.log2(pool)
}

/** Map a zxcvbn 0–4 score to a risk band for the shared colour scale. */
export function scoreToRiskBand(score: number): RiskBand {
  if (score >= 3) return 'safe'
  if (score === 2) return 'warn'
  return 'danger'
}

/**
 * Analyse `password` and return the combined strength result.
 *
 * Runs the naive charset model and zxcvbn-ts, and bundles both. The
 * authoritative score is `result.score` (zxcvbn's 0–4 score).
 */
export function analyzeStrength(password: string): StrengthResult {
  ensureZxcvbnConfigured()
  const z = zxcvbn(password)
  const score = z.score
  const seconds = z.crackTimesSeconds

  return {
    score,
    scoreLabel: SCORE_LABELS[score] ?? 'Unknown',
    riskBand: scoreToRiskBand(score),
    naiveEntropyBits: naiveEntropyBits(password),
    poolSize: charsetPoolSize(password),
    classesUsed: countCharClasses(password),
    length: password.length,
    guessesLog10: z.guessesLog10,
    crackTimes: {
      onlineThrottled: formatCrackTime(Number(seconds.onlineThrottling100PerHour)),
      onlineUnthrottled: formatCrackTime(Number(seconds.onlineNoThrottling10PerSecond)),
      offlineSlowHash: formatCrackTime(Number(seconds.offlineSlowHashing1e4PerSecond)),
      offlineFastHash: formatCrackTime(Number(seconds.offlineFastHashing1e10PerSecond)),
    },
    warning: z.feedback.warning ?? '',
    suggestions: z.feedback.suggestions ?? [],
  }
}
