/**
 * End-to-end tests for the PassSentinel website.
 *
 * These run against the built + previewed site (see playwright.config.ts) so
 * any GitHub Pages `base`-path regression surfaces. The HIBP API is mocked via
 * Playwright route interception, making the suite deterministic and offline.
 * A separate `@live` test (excluded by default) exercises the real API.
 */

import { type Page, expect, test } from '@playwright/test'
import { rangeBodyForPrefix } from './fixtures/hibp-mock'

/** The range-API URL pattern; the last path segment is the 5-char prefix. */
const HIBP_RANGE_GLOB = 'https://api.pwnedpasswords.com/range/*'

/**
 * Intercept every HIBP range request and answer it from the local fixture.
 * Returns the list of prefixes the page requested, for later assertions.
 */
async function mockHibp(page: Page): Promise<string[]> {
  const requestedPrefixes: string[] = []
  await page.route(HIBP_RANGE_GLOB, async (route) => {
    const url = new URL(route.request().url())
    const prefix = url.pathname.split('/').pop() ?? ''
    requestedPrefixes.push(prefix)
    await route.fulfill({
      status: 200,
      contentType: 'text/plain',
      body: rangeBodyForPrefix(prefix),
    })
  })
  return requestedPrefixes
}

test.describe('PassSentinel — strength meter', () => {
  test('page loads with the brand and an idle meter', async ({ page }) => {
    await page.goto('./')
    await expect(page).toHaveTitle(/PassSentinel/)
    await expect(page.locator('.site-header__brand')).toContainText('PassSentinel')
    // The privacy guarantee is stated prominently on the page.
    await expect(page.locator('.privacy-note')).toContainText(
      'never leaves this browser',
    )
    // The meter starts idle.
    await expect(page.locator('#meter-label')).toHaveText(/Awaiting input/)
  })

  test('typing a weak password shows a weak, red meter', async ({ page }) => {
    await page.goto('./')
    await page.fill('#pw', 'password123')

    const label = page.locator('#meter-label')
    await expect(label).toHaveText(/Very weak|Weak/)
    // The meter label carries the danger (red) modifier class.
    await expect(label).toHaveClass(/meter-label--danger/)
    // The meter fill is red.
    await expect(page.locator('#meter-fill')).toHaveClass(/meter__fill--danger/)
    // The score readout shows a low score.
    await expect(page.locator('#score-readout')).toHaveText(/[01]\/4/)
  })

  test('typing a strong passphrase shows a strong, green meter', async ({ page }) => {
    await page.goto('./')
    await page.fill('#pw', 'correct-horse-battery-staple-quartz-97')

    const label = page.locator('#meter-label')
    await expect(label).toHaveText(/Strong|Very strong/)
    await expect(label).toHaveClass(/meter-label--safe/)
    await expect(page.locator('#meter-fill')).toHaveClass(/meter__fill--safe/)
    await expect(page.locator('#score-readout')).toHaveText(/[34]\/4/)
  })

  test('crack-time estimates update as the password changes', async ({ page }) => {
    await page.goto('./')

    // A weak password: at least one scenario should crack effectively instantly.
    await page.fill('#pw', 'abc')
    const weakCrack = (await page.locator('.crack-cell__value').allTextContents())
      .join(' | ')
    expect(weakCrack.toLowerCase()).toContain('instantly')

    // A strong password: the crack-time grid changes to much longer durations.
    await page.fill('#pw', 'correct-horse-battery-staple-quartz-97')
    const strongCrack = (await page.locator('.crack-cell__value').allTextContents())
      .join(' | ')
    expect(strongCrack).not.toEqual(weakCrack)
    // A strong password resists a slow-hash offline attack for a long time.
    expect(strongCrack.toLowerCase()).toMatch(/year|century|centuries/)
  })

  test('zxcvbn warning and suggestions are shown for a weak password', async ({
    page,
  }) => {
    await page.goto('./')
    await page.fill('#pw', 'password')
    // The feedback block becomes visible with a warning.
    await expect(page.locator('#feedback-block')).toBeVisible()
    await expect(page.locator('#feedback-warning')).toBeVisible()
  })

  test('transparent pattern findings list common-password weaknesses', async ({
    page,
  }) => {
    await page.goto('./')
    await page.fill('#pw', 'qwerty1234')
    const patterns = page.locator('#patterns-list')
    await expect(patterns).toBeVisible()
    // The keyboard-walk finding should appear.
    await expect(patterns).toContainText(/keyboard walk/i)
  })

  test('the show/hide toggle reveals and re-masks the password', async ({ page }) => {
    await page.goto('./')
    const input = page.locator('#pw')
    const toggle = page.locator('#toggle-visibility')

    await input.fill('secret-value')
    await expect(input).toHaveAttribute('type', 'password')

    await toggle.click()
    await expect(input).toHaveAttribute('type', 'text')
    await expect(toggle).toHaveText('Hide')

    await toggle.click()
    await expect(input).toHaveAttribute('type', 'password')
    await expect(toggle).toHaveText('Show')
  })

  test('clearing the input returns the meter to the idle state', async ({ page }) => {
    await page.goto('./')
    await page.fill('#pw', 'password123')
    await expect(page.locator('#details')).toBeVisible()

    await page.fill('#pw', '')
    await expect(page.locator('#meter-label')).toHaveText(/Awaiting input/)
    await expect(page.locator('#details')).toBeHidden()
  })
})

test.describe('PassSentinel — breach check (mocked HIBP)', () => {
  test('a breached password produces a clear "breached" result', async ({ page }) => {
    const prefixes = await mockHibp(page)
    await page.goto('./')

    await page.fill('#pw', 'password')
    await page.click('#check-breaches')

    const result = page.locator('#breach-result')
    await expect(result).toBeVisible()
    await expect(result).toHaveClass(/breach-result--danger/)
    await expect(page.locator('#breach-headline')).toHaveText(/Found in known data breaches/)

    // The page sent exactly one request, and only the 5-char prefix.
    expect(prefixes).toHaveLength(1)
    expect(prefixes[0]).toBe('5BAA6')
    expect(prefixes[0]).toHaveLength(5)
  })

  test('a non-breached password produces a clear "safe" result', async ({ page }) => {
    const prefixes = await mockHibp(page)
    await page.goto('./')

    await page.fill('#pw', 'correct-horse-battery-staple-quartz-97')
    await page.click('#check-breaches')

    const result = page.locator('#breach-result')
    await expect(result).toBeVisible()
    await expect(result).toHaveClass(/breach-result--safe/)
    await expect(page.locator('#breach-headline')).toHaveText(/Not found in any known breach/)

    // Still only a 5-character prefix was transmitted.
    expect(prefixes).toHaveLength(1)
    expect(prefixes[0]).toHaveLength(5)
  })

  test('the breach check shows an unavailable state on a network error', async ({
    page,
  }) => {
    // Abort every HIBP request to simulate the service being unreachable.
    await page.route(HIBP_RANGE_GLOB, (route) => route.abort('failed'))
    await page.goto('./')

    await page.fill('#pw', 'password')
    await page.click('#check-breaches')

    const result = page.locator('#breach-result')
    await expect(result).toBeVisible()
    await expect(result).toHaveClass(/breach-result--neutral/)
    await expect(page.locator('#breach-headline')).toHaveText(/unavailable/i)
  })

  test('editing the password after a check clears the stale breach result', async ({
    page,
  }) => {
    await mockHibp(page)
    await page.goto('./')

    await page.fill('#pw', 'password')
    await page.click('#check-breaches')
    await expect(page.locator('#breach-result')).toBeVisible()

    // Changing the password invalidates the previous result.
    await page.fill('#pw', 'password-modified')
    await expect(page.locator('#breach-result')).toBeHidden()
  })
})
