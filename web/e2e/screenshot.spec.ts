/**
 * Captures the README screenshot.
 *
 * Not a test of behaviour — it drives the page into a representative state
 * (a weak password analysed, a mocked breach hit shown) and writes a full-page
 * PNG to `docs/screenshot.png`. Runs as part of the normal Playwright suite so
 * the screenshot stays in sync with the UI.
 */

import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { expect, test } from '@playwright/test'
import { rangeBodyForPrefix } from './fixtures/hibp-mock'

const HIBP_RANGE_GLOB = 'https://api.pwnedpasswords.com/range/*'

// docs/ lives at the repo root, one level above web/.
const SCREENSHOT_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../docs/screenshot.png',
)

test('capture docs screenshot', async ({ page }) => {
  // Mock HIBP so the screenshot shows a deterministic breach result.
  await page.route(HIBP_RANGE_GLOB, async (route) => {
    const prefix = new URL(route.request().url()).pathname.split('/').pop() ?? ''
    await route.fulfill({
      status: 200,
      contentType: 'text/plain',
      body: rangeBodyForPrefix(prefix),
    })
  })

  await page.setViewportSize({ width: 1180, height: 1400 })
  await page.goto('./')

  // Analyse a weak password and run the (mocked) breach check so the captured
  // page shows the meter, crack times, findings and a breach verdict together.
  await page.fill('#pw', 'password')
  await page.click('#check-breaches')
  await expect(page.locator('#breach-result')).toBeVisible()

  await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true })
})
