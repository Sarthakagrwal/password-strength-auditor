// `defineConfig` is imported from `vitest/config` so the `test` block is typed.
import { defineConfig } from 'vitest/config'

// `base` MUST match the GitHub repo name, or the deployed Project Pages site
// loads its assets from the wrong path and renders blank.
export default defineConfig({
  base: '/password-strength-auditor/',
  test: {
    environment: 'jsdom',
    globals: true,
    // Playwright specs live under e2e/ and are run by Playwright, not Vitest.
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
})
