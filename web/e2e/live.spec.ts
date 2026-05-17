/**
 * Optional live test against the real Have I Been Pwned API.
 *
 * Tagged `@live` and therefore EXCLUDED from the default Playwright run
 * (see `grepInvert: /@live/` in playwright.config.ts). It exists so the real
 * k-anonymity round-trip can be verified on demand:
 *
 *   npx playwright test --grep @live
 *
 * It requires network access and is intentionally kept out of CI's default run.
 */

import { expect, test } from '@playwright/test'

test('@live breached password is detected against the real HIBP API', async ({
  page,
}) => {
  // No route interception here — this hits api.pwnedpasswords.com for real.
  await page.goto('./')

  // "password" is, unsurprisingly, in the real breach corpus.
  await page.fill('#pw', 'password')
  await page.click('#check-breaches')

  const result = page.locator('#breach-result')
  await expect(result).toBeVisible({ timeout: 15_000 })
  await expect(result).toHaveClass(/breach-result--danger/)
  await expect(page.locator('#breach-headline')).toHaveText(
    /Found in known data breaches/,
  )
})
