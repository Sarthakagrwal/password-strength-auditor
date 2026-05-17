/**
 * Crack-time duration formatting.
 *
 * zxcvbn-ts reports crack times as raw seconds for each attacker scenario; this
 * module turns those seconds into compact, human-readable strings such as
 * `"instantly"`, `"3 minutes"`, `"2 centuries"` or `"5e+7 years"`. The logic
 * mirrors the Python `pwaudit.entropy.format_duration` so the CLI and the
 * website agree.
 */

const MINUTE = 60
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const MONTH = 30 * DAY
const YEAR = 365 * DAY
const CENTURY = 100 * YEAR

/** Time units as `[size-in-seconds, singular-name]`, smallest to largest. */
const TIME_UNITS: ReadonlyArray<readonly [number, string]> = [
  [1, 'second'],
  [MINUTE, 'minute'],
  [HOUR, 'hour'],
  [DAY, 'day'],
  [MONTH, 'month'],
  [YEAR, 'year'],
  [CENTURY, 'century'],
]

/** Return `"<count> <unit>"` with English pluralisation of `singular`. */
function pluralize(count: number, singular: string): string {
  if (count === 1) return `1 ${singular}`
  if (singular === 'century') return `${count} centuries`
  return `${count} ${singular}s`
}

/**
 * Format a duration in `seconds` as a compact human-readable string.
 *
 * The largest unit whose value is at least 1 is chosen, so 90 seconds reads as
 * `"2 minutes"` rather than a tiny fraction of a century. Durations beyond
 * ~100,000 years fall back to scientific-notation years. Negative or NaN inputs
 * are treated as `"instantly"`.
 */
export function formatCrackTime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 1) {
    return 'instantly'
  }

  // Beyond ~100,000 years any named unit is unwieldy: use scientific years.
  if (seconds / YEAR >= 1e5) {
    return `${(seconds / YEAR).toExponential(0)} years`
  }

  // Pick the largest unit whose value is >= 1 (walk largest -> smallest).
  for (let i = TIME_UNITS.length - 1; i >= 0; i--) {
    const [size, name] = TIME_UNITS[i]
    const value = seconds / size
    if (value >= 1) {
      return pluralize(Math.round(value), name)
    }
  }

  // seconds is in [1, 60): report in seconds.
  return pluralize(Math.round(seconds), 'second')
}

/**
 * Format a guess count, given its base-10 logarithm, as a readable string.
 *
 * zxcvbn reports `guessesLog10`; taking the log directly avoids overflowing a
 * float for very large search spaces. Counts under 100,000 are shown literally
 * with thousands separators; larger counts use a `10^n` form.
 */
export function formatGuessesFromLog10(guessesLog10: number): string {
  if (!Number.isFinite(guessesLog10) || guessesLog10 < 0) return '0'
  if (guessesLog10 < 5) {
    return Math.round(10 ** guessesLog10).toLocaleString('en-US')
  }
  return `10^${guessesLog10.toFixed(1)}`
}
