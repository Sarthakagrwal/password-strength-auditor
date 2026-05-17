/**
 * PassSentinel — password strength auditor (client-side entry point).
 *
 * Builds the page, wires the live strength meter to the password input, and
 * runs the on-demand HIBP breach check. Everything happens in the browser:
 * the password is never transmitted; only the first 5 characters of its SHA-1
 * hash are sent to Have I Been Pwned (the k-anonymity model).
 */

import './styles/theme.css'
import './styles/app.css'

import { formatGuessesFromLog10 } from './crackTime'
import { checkPassword } from './hibp'
import { findPatterns } from './patterns'
import { type RiskBand, type StrengthResult, analyzeStrength } from './strength'

const GITHUB_URL = 'https://github.com/Sarthakagrwal/password-strength-auditor'

// --- Small DOM helpers ----------------------------------------------------------

/** Create an element with optional class and text content. */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

/** Query a required element, throwing a clear error if it is missing. */
function need<T extends Element>(selector: string): T {
  const node = document.querySelector<T>(selector)
  if (!node) throw new Error(`expected element: ${selector}`)
  return node
}

// --- Static page markup ---------------------------------------------------------

/**
 * The page shell. Dynamic regions are addressed later by id; this string holds
 * only the structure and the always-visible explanatory copy.
 */
const PAGE_HTML = /* html */ `
  <header class="site-header">
    <div class="wrap site-header__inner">
      <a class="site-header__brand" href="./" aria-label="PassSentinel home">
        <span class="logo">PS</span>
        <span>PassSentinel</span>
      </a>
      <nav class="site-header__nav">
        <a href="#how-it-works">How it works</a>
        <a href="${GITHUB_URL}" target="_blank" rel="noopener noreferrer">GitHub</a>
      </nav>
    </div>
  </header>

  <main class="wrap">
    <section class="hero hero--compact">
      <span class="eyebrow">Password security &middot; HIBP k-anonymity</span>
      <h1>Audit a password's strength &amp; breach exposure</h1>
      <p class="lede">
        PassSentinel scores how hard a password is to guess and checks whether it
        has appeared in real-world data breaches &mdash; without the password
        ever leaving this browser.
      </p>
    </section>

    <div class="privacy-note" role="note">
      <span aria-hidden="true">&#128274;</span>
      <span>
        <strong>Your password never leaves this browser.</strong>
        Strength analysis runs entirely on this page. For the breach check, only
        the first 5 characters of the password's SHA-1 hash are sent to Have I
        Been Pwned &mdash; never the password and never the full hash.
      </span>
    </div>

    <section class="section">
      <div class="card card--pad-lg auditor">
        <div class="field pw-input">
          <label for="pw">Password to audit</label>
          <input
            type="password"
            id="pw"
            class="input--mono"
            autocomplete="off"
            autocapitalize="off"
            autocorrect="off"
            spellcheck="false"
            placeholder="Type a password — analysis is live"
          />
          <button
            type="button"
            id="toggle-visibility"
            class="btn btn--ghost btn--sm pw-input__toggle"
            aria-pressed="false"
          >
            Show
          </button>
        </div>

        <div id="strength-panel">
          <div class="meter-row">
            <span class="meter-label meter-label--idle" id="meter-label">
              Awaiting input
            </span>
            <span class="muted mono" id="score-readout">&mdash;/4</span>
          </div>
          <div class="meter" role="progressbar" aria-label="Password strength"
               aria-valuemin="0" aria-valuemax="4" aria-valuenow="0">
            <div class="meter__fill" id="meter-fill"></div>
          </div>
          <p class="idle-hint mt-3" id="idle-hint">
            Start typing above to see a live strength estimate.
          </p>
        </div>

        <div id="details" class="hidden auditor">
          <div>
            <div class="card__title">Strength estimates</div>
            <div class="estimates">
              <div class="estimate">
                <div class="estimate__label">Naive charset entropy</div>
                <div class="estimate__value" id="naive-bits">&mdash;</div>
                <div class="estimate__note">
                  Optimistic &mdash; assumes every character is random.
                </div>
              </div>
              <div class="estimate">
                <div class="estimate__label">zxcvbn estimate</div>
                <div class="estimate__value" id="zxcvbn-guesses">&mdash;</div>
                <div class="estimate__note">
                  Realistic &mdash; the number to trust.
                </div>
              </div>
            </div>
          </div>

          <div>
            <div class="card__title">Estimated time to crack (zxcvbn)</div>
            <div class="crack-grid" id="crack-grid"></div>
          </div>

          <div id="feedback-block" class="feedback hidden">
            <div class="card__title">Feedback</div>
            <div id="feedback-warning" class="feedback__warning hidden"></div>
            <ul id="feedback-suggestions"></ul>
          </div>

          <div id="patterns-block" class="hidden">
            <div class="card__title">Pattern findings</div>
            <ul class="reasons" id="patterns-list"></ul>
          </div>

          <div>
            <div class="card__title">Breach check &mdash; Have I Been Pwned</div>
            <p class="muted" style="font-size: 0.88rem; margin-bottom: 12px;">
              Checks the password against billions of breached credentials using
              k-anonymity. Only a 5-character hash prefix is sent.
            </p>
            <div class="flex gap-3" style="align-items: center; flex-wrap: wrap;">
              <button type="button" id="check-breaches" class="btn btn--primary">
                Check breaches
              </button>
              <span id="breach-status" class="muted" style="font-size: 0.9rem;"></span>
            </div>
            <div id="breach-result" class="breach-result breach-result--neutral hidden mt-4">
              <span class="breach-result__icon" id="breach-icon"></span>
              <span class="breach-result__text">
                <strong id="breach-headline"></strong>
                <span id="breach-detail"></span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="how-it-works">
      <h2>How it works</h2>
      <p class="muted mt-3" style="max-width: 680px;">
        Two independent questions decide whether a password is safe to use, and
        a breach hit always wins.
      </p>
      <div class="grid grid-2 mt-4">
        <div class="card">
          <div class="card__title">1 &middot; How strong is it?</div>
          <p class="muted">
            A naive model multiplies length by the bits per character of its
            character pool &mdash; but that assumes randomness humans rarely
            achieve. The
            <a href="https://github.com/zxcvbn-ts/zxcvbn" target="_blank"
               rel="noopener noreferrer">zxcvbn</a>
            estimator instead searches for dictionary words, names, dates,
            keyboard patterns and l33t-speak, and reports the guesses an informed
            attacker actually needs. PassSentinel shows both so you can see the
            gap &mdash; and trusts zxcvbn.
          </p>
        </div>
        <div class="card">
          <div class="card__title">2 &middot; Has it already leaked?</div>
          <p class="muted">
            Strength is irrelevant if the password is already public. The
            breach check uses the
            <a href="https://haveibeenpwned.com/Passwords" target="_blank"
               rel="noopener noreferrer">HIBP Pwned Passwords</a>
            range API with k-anonymity (see the steps below). A password found
            in breach data is reported <strong>unsafe no matter how strong it
            scores</strong> &mdash; attackers already have it.
          </p>
        </div>
      </div>

      <div class="card mt-4">
        <div class="card__title">The k-anonymity breach check, step by step</div>
        <div class="grid mt-3" style="gap: 16px;">
          <div class="explainer-step">
            <span class="explainer-step__num">1</span>
            <div class="explainer-step__body">
              <h3>Hash locally</h3>
              <p>The browser computes SHA-1 of the password using the Web Crypto API. Nothing is sent yet.</p>
            </div>
          </div>
          <div class="explainer-step">
            <span class="explainer-step__num">2</span>
            <div class="explainer-step__body">
              <h3>Send only a 5-character prefix</h3>
              <p>The 40-character hash is split into a 5-char prefix and a 35-char suffix. Only the prefix is requested from the API.</p>
            </div>
          </div>
          <div class="explainer-step">
            <span class="explainer-step__num">3</span>
            <div class="explainer-step__body">
              <h3>Match the suffix in the browser</h3>
              <p>The API returns every hash suffix sharing that prefix. PassSentinel matches your suffix locally &mdash; the server never learns which password was checked.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="site-footer">
    <div class="wrap footer-row">
      <span>
        Built by Sarthak Aggarwal as part of a cybersecurity learning portfolio.
      </span>
      <span>
        Breach data &mdash;
        <a href="https://haveibeenpwned.com/Passwords" target="_blank"
           rel="noopener noreferrer">Have I Been Pwned Pwned Passwords API</a>.
        Strength estimation by
        <a href="https://github.com/zxcvbn-ts/zxcvbn" target="_blank"
           rel="noopener noreferrer">zxcvbn-ts</a>.
      </span>
    </div>
  </footer>
`

// --- Crack-time scenario labels -------------------------------------------------

const CRACK_SCENARIOS: ReadonlyArray<readonly [keyof StrengthResult['crackTimes'], string]> = [
  ['onlineThrottled', 'Online, rate-limited (~100/hr)'],
  ['onlineUnthrottled', 'Online, no throttle (~10/s)'],
  ['offlineSlowHash', 'Offline, slow hash / bcrypt (~1e4/s)'],
  ['offlineFastHash', 'Offline, fast hash on GPU (~1e10/s)'],
]

// --- Rendering helpers ----------------------------------------------------------

/** Map a risk band to its meter-fill modifier class. */
function meterClassFor(band: RiskBand): string {
  return `meter__fill meter__fill--${band}`
}

/** Map a risk band to its meter-label modifier class. */
function labelClassFor(band: RiskBand): string {
  return `meter-label meter-label--${band}`
}

/** Read the current password input value. */
function currentPassword(): string {
  return need<HTMLInputElement>('#pw').value
}

/** Render the live strength panel for a freshly analysed password. */
function renderStrength(result: StrengthResult): void {
  const fill = need<HTMLElement>('#meter-fill')
  const label = need<HTMLElement>('#meter-label')
  const readout = need<HTMLElement>('#score-readout')
  const meter = need<HTMLElement>('.meter')

  // Meter width: scores 0–4 mapped to 20/40/60/80/100% (score 0 still shows a
  // sliver of red so the bar is never empty for a typed password).
  const widthPct = Math.max(8, (result.score + 1) * 20)
  fill.className = meterClassFor(result.riskBand)
  fill.style.width = `${widthPct}%`

  label.className = labelClassFor(result.riskBand)
  label.textContent = result.scoreLabel
  readout.textContent = `${result.score}/4`
  meter.setAttribute('aria-valuenow', String(result.score))

  // Estimates. zxcvbn's number is a guess count; very large counts use 10^n.
  need<HTMLElement>('#naive-bits').textContent = `${result.naiveEntropyBits.toFixed(0)} bits`
  need<HTMLElement>('#zxcvbn-guesses').textContent =
    `${formatGuessesFromLog10(result.guessesLog10)} guesses`

  // Crack-time grid.
  const grid = need<HTMLElement>('#crack-grid')
  grid.replaceChildren()
  for (const [key, scenarioLabel] of CRACK_SCENARIOS) {
    const cell = el('div', 'crack-cell')
    cell.append(
      el('div', 'crack-cell__scenario', scenarioLabel),
      el('div', 'crack-cell__value', result.crackTimes[key]),
    )
    grid.append(cell)
  }

  // zxcvbn feedback.
  const feedbackBlock = need<HTMLElement>('#feedback-block')
  const warning = need<HTMLElement>('#feedback-warning')
  const suggestions = need<HTMLElement>('#feedback-suggestions')
  suggestions.replaceChildren()
  const hasWarning = result.warning.trim().length > 0
  const hasSuggestions = result.suggestions.length > 0
  if (hasWarning) {
    warning.textContent = `! ${result.warning}`
    warning.classList.remove('hidden')
  } else {
    warning.classList.add('hidden')
  }
  for (const suggestion of result.suggestions) {
    suggestions.append(el('li', undefined, suggestion))
  }
  feedbackBlock.classList.toggle('hidden', !hasWarning && !hasSuggestions)

  // Transparent pattern findings.
  const patternsBlock = need<HTMLElement>('#patterns-block')
  const patternsList = need<HTMLElement>('#patterns-list')
  patternsList.replaceChildren()
  const findings = findPatterns(currentPassword())
  for (const finding of findings) {
    const li = el('li')
    li.append(el('span', 'dot dot--danger'), el('span', undefined, finding.reason))
    patternsList.append(li)
  }
  patternsBlock.classList.toggle('hidden', findings.length === 0)
}

/** Clear any previous breach result (e.g. after the password changes). */
function resetBreachUi(): void {
  need<HTMLElement>('#breach-result').classList.add('hidden')
  need<HTMLElement>('#breach-status').textContent = ''
  const button = need<HTMLButtonElement>('#check-breaches')
  button.disabled = false
  button.textContent = 'Check breaches'
}

/** Reset the panel to its idle (no-input) state. */
function renderIdle(): void {
  const fill = need<HTMLElement>('#meter-fill')
  const label = need<HTMLElement>('#meter-label')
  const readout = need<HTMLElement>('#score-readout')

  fill.className = 'meter__fill'
  fill.style.width = '0%'
  label.className = 'meter-label meter-label--idle'
  label.textContent = 'Awaiting input'
  readout.textContent = '—/4'
  need<HTMLElement>('.meter').setAttribute('aria-valuenow', '0')

  need<HTMLElement>('#details').classList.add('hidden')
  need<HTMLElement>('#idle-hint').classList.remove('hidden')
  resetBreachUi()
}

// --- Breach-check rendering -----------------------------------------------------

/** Show a definitive breached / safe / unavailable breach result. */
function renderBreachResult(
  state: 'breached' | 'safe' | 'unavailable',
  count: number,
): void {
  const box = need<HTMLElement>('#breach-result')
  const icon = need<HTMLElement>('#breach-icon')
  const headline = need<HTMLElement>('#breach-headline')
  const detail = need<HTMLElement>('#breach-detail')

  box.classList.remove(
    'hidden',
    'breach-result--safe',
    'breach-result--danger',
    'breach-result--neutral',
  )

  if (state === 'breached') {
    box.classList.add('breach-result--danger')
    icon.textContent = '⚠'
    headline.textContent = 'Found in known data breaches'
    const times = count === 1 ? 'time' : 'times'
    detail.textContent =
      `This password appears ${count.toLocaleString('en-US')} ${times} in breach corpora. ` +
      'Treat it as compromised and never use it anywhere.'
  } else if (state === 'safe') {
    box.classList.add('breach-result--safe')
    icon.textContent = '✓'
    headline.textContent = 'Not found in any known breach'
    detail.textContent =
      'This password was not in the HIBP Pwned Passwords corpus. ' +
      'That is good, but not a guarantee of strength — read the score above.'
  } else {
    box.classList.add('breach-result--neutral')
    icon.textContent = '—'
    headline.textContent = 'Breach check unavailable'
    detail.textContent =
      'Could not reach Have I Been Pwned. Check your connection and try again.'
  }
}

// --- Event handlers -------------------------------------------------------------

/** Handle every change to the password field. */
function onPasswordInput(): void {
  const password = currentPassword()
  // Any edit invalidates a previous breach result.
  resetBreachUi()

  if (password.length === 0) {
    renderIdle()
    return
  }
  need<HTMLElement>('#details').classList.remove('hidden')
  need<HTMLElement>('#idle-hint').classList.add('hidden')
  renderStrength(analyzeStrength(password))
}

/** Toggle the password field between masked and revealed. */
function onToggleVisibility(): void {
  const input = need<HTMLInputElement>('#pw')
  const button = need<HTMLButtonElement>('#toggle-visibility')
  const reveal = input.type === 'password'
  input.type = reveal ? 'text' : 'password'
  button.textContent = reveal ? 'Hide' : 'Show'
  button.setAttribute('aria-pressed', String(reveal))
}

/** Run the HIBP breach check for the current password. */
async function onCheckBreaches(): Promise<void> {
  const password = currentPassword()
  if (password.length === 0) return

  const button = need<HTMLButtonElement>('#check-breaches')
  const status = need<HTMLElement>('#breach-status')

  button.disabled = true
  button.textContent = 'Checking…'
  status.textContent = 'Sending only a 5-character hash prefix…'
  need<HTMLElement>('#breach-result').classList.add('hidden')

  try {
    const result = await checkPassword(password)
    // Guard against a race: the user may have edited the field mid-request.
    if (currentPassword() !== password) {
      resetBreachUi()
      return
    }
    renderBreachResult(result.breached ? 'breached' : 'safe', result.count)
    status.textContent = ''
  } catch {
    // HibpUnavailableError (or any unexpected error) -> "unavailable" state.
    renderBreachResult('unavailable', 0)
    status.textContent = ''
  } finally {
    button.disabled = false
    button.textContent = 'Check breaches again'
  }
}

/** Mount the application into `#app` and attach all event listeners. */
function mount(): void {
  const app = need<HTMLDivElement>('#app')
  app.innerHTML = PAGE_HTML

  need<HTMLInputElement>('#pw').addEventListener('input', onPasswordInput)
  need<HTMLButtonElement>('#toggle-visibility').addEventListener('click', onToggleVisibility)
  need<HTMLButtonElement>('#check-breaches').addEventListener('click', () => {
    void onCheckBreaches()
  })

  renderIdle()
}

mount()
