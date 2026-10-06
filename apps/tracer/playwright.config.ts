/** Runs browser checks against the built tracer and its clearly marked test double. */
import { defineConfig, devices } from "playwright/test";

export default defineConfig({
  testDir: "./test",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  // All workers share one auth/terminal test-double process and its owner state.
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: "list",
  outputDir: "./test-results",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:4173",
    launchOptions: {
      // Keep a headless visible-surface probe on the renderer's foreground frame cadence.
      args: process.env.TRACER_CHROMIUM_FLAGS === undefined
        ? ["--disable-renderer-backgrounding"]
        : process.env.TRACER_CHROMIUM_FLAGS.split(/\s+/).filter(Boolean),
    },
    // Ceremonies contain capabilities and recovery words. Capture only explicit
    // access/terminal screenshots, never network traces or arbitrary failure pages.
    trace: "off",
    screenshot: "off",
  },
  webServer: {
    command: "bun run build && bun run test/mock-server.ts",
    url: "http://localhost:4173/health",
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
