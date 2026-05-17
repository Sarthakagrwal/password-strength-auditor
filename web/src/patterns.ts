/**
 * Transparent password-weakness pattern detectors (browser side).
 *
 * Each detector targets one well-understood weakness and, when it fires,
 * returns a plain-language reason. These mirror the Python `pwaudit.patterns`
 * detectors so the CLI and the website agree on what counts as a weak pattern.
 * Unlike the statistical zxcvbn model, every check here is small and readable.
 */

/** A single detected weakness pattern. */
export interface PatternFinding {
  /** Stable identifier, e.g. `"keyboard_walk"`. */
  code: string
  /** Human-readable explanation of the weakness. */
  reason: string
}

/** Physical QWERTY keyboard rows, used for keyboard-walk detection. */
const KEYBOARD_ROWS: readonly string[] = [
  '1234567890',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
]

/** Leetspeak character -> the letter it commonly replaces. */
const LEET_MAP: Readonly<Record<string, string>> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '9': 'g',
  '@': 'a',
  $: 's',
  '!': 'i',
  '+': 't',
  '(': 'c',
}

/**
 * A compact set of very common passwords (lower-cased).
 *
 * Deliberately small — a fast "is this obvious" check. The authoritative breach
 * answer comes from the HIBP range API (see {@link file://./hibp.ts}).
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  '123456',
  '12345',
  '123456789',
  '12345678',
  '1234567',
  '1234567890',
  '1234',
  '111111',
  '123123',
  '000000',
  '1q2w3e4r',
  '1q2w3e',
  '1qaz2wsx',
  'password',
  'password1',
  'password123',
  'passw0rd',
  'p@ssw0rd',
  'p@ssword',
  'admin',
  'root',
  'letmein',
  'welcome',
  'welcome1',
  'secret',
  'changeme',
  'test',
  'test123',
  'qwerty',
  'qwertyuiop',
  'qwerty123',
  'abc123',
  'abcd1234',
  'iloveyou',
  'monkey',
  'dragon',
  'football',
  'baseball',
  'sunshine',
  'princess',
  'shadow',
  'master',
  'superman',
  'trustno1',
])

const MIN_RUN = 4

/** True if `password` contains an ascending/descending run of `minRun`+. */
function hasSequentialRun(password: string, minRun = MIN_RUN): boolean {
  const pw = password.toLowerCase()
  if (pw.length < minRun) return false
  let asc = 1
  let desc = 1
  for (let i = 1; i < pw.length; i++) {
    const delta = pw.charCodeAt(i) - pw.charCodeAt(i - 1)
    asc = delta === 1 ? asc + 1 : 1
    desc = delta === -1 ? desc + 1 : 1
    if (asc >= minRun || desc >= minRun) return true
  }
  return false
}

/** True if a single character repeats `minRun`+ times in a row. */
function hasRepeatRun(password: string, minRun = MIN_RUN): boolean {
  const pw = password.toLowerCase()
  if (pw.length < minRun) return false
  let run = 1
  for (let i = 1; i < pw.length; i++) {
    run = pw[i] === pw[i - 1] ? run + 1 : 1
    if (run >= minRun) return true
  }
  return false
}

/** True if `password` contains a straight QWERTY-row walk of `minRun`+. */
function hasKeyboardWalk(password: string, minRun = MIN_RUN): boolean {
  const pw = password.toLowerCase()
  if (pw.length < minRun) return false
  for (const row of KEYBOARD_ROWS) {
    const reversed = [...row].reverse().join('')
    for (let start = 0; start <= pw.length - minRun; start++) {
      const window = pw.slice(start, start + minRun)
      if (row.includes(window) || reversed.includes(window)) return true
    }
  }
  return false
}

/** Replace leetspeak characters in `password` with their plain letters. */
function normalizeLeet(password: string): string {
  return [...password.toLowerCase()].map((c) => LEET_MAP[c] ?? c).join('')
}

/**
 * If `password` is leetspeak for a common password, return that common word;
 * otherwise return null. Requires at least one actual leet substitution so a
 * plain common password is not double-reported.
 */
function leetspeakOfCommon(password: string): string | null {
  const hasLeetChar = [...password.toLowerCase()].some((c) => c in LEET_MAP)
  if (!hasLeetChar) return null
  const normalized = normalizeLeet(password)
  if (normalized !== password.toLowerCase() && COMMON_PASSWORDS.has(normalized)) {
    return normalized
  }
  return null
}

/** Plausible 4-digit year, 1900–2039. */
const YEAR_RE = /(?:19\d\d|20[0-3]\d)/

/**
 * Run every pattern detector against `password`.
 *
 * Returns one {@link PatternFinding} per weakness found; an empty array means no
 * transparent detector fired (which does not by itself prove the password is
 * strong — see {@link file://./strength.ts}).
 */
export function findPatterns(password: string): PatternFinding[] {
  const findings: PatternFinding[] = []
  if (!password) return findings

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    findings.push({
      code: 'common_password',
      reason:
        'This is one of the most common passwords in breach corpora — it would be guessed almost immediately.',
    })
  }

  const leetOf = leetspeakOfCommon(password)
  if (leetOf !== null) {
    findings.push({
      code: 'leetspeak',
      reason: `This is leetspeak for the common password "${leetOf}". Character swaps like a→@ or o→0 are the first thing crackers try.`,
    })
  }

  if (hasSequentialRun(password)) {
    findings.push({
      code: 'sequential',
      reason:
        'Contains a sequential run (e.g. "abcd" or "1234"). Sequences add almost no real randomness.',
    })
  }

  if (hasRepeatRun(password)) {
    findings.push({
      code: 'repeat',
      reason:
        'Contains a character repeated four or more times in a row (e.g. "aaaa"). Repeats barely expand the search space.',
    })
  }

  if (hasKeyboardWalk(password)) {
    findings.push({
      code: 'keyboard_walk',
      reason:
        'Contains a keyboard walk (e.g. "qwerty" or "asdf"). Adjacent-key patterns are in every cracking wordlist.',
    })
  }

  const yearMatch = password.match(YEAR_RE)
  if (yearMatch) {
    findings.push({
      code: 'year',
      reason: `Contains the year "${yearMatch[0]}". Years (birthdays, graduations) are highly predictable and heavily targeted.`,
    })
  }

  return findings
}
