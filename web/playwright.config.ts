import { defineConfig, devices } from '@playwright/test'

// E2E tests run against the *built and previewed* site (not `vite dev`) so that
// any `base`-path regression surfaces, exactly as it would on GitHub Pages.
const BASE_PATH = '/password-strength-auditor/'
const PORT = 4173

export default defineConfig({
  testDir: './e2e',
  // The `@live` tag marks tests that hit the real HIBP API. They are excluded
  // from the default run so the suite is deterministic and offline. To run them
  // (network required), set RUN_LIVE=1, e.g. `RUN_LIVE=1 npm run test:e2e`.
  grepInvert: process.env.RUN_LIVE ? undefined : /@live/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE_PATH}`,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm run build && npm run preview',
    url: `http://localhost:${PORT}${BASE_PATH}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
