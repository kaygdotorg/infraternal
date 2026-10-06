/** Runs browser checks against the built tracer and its clearly marked test double. */
import { defineConfig, devices } from "playwright/test";

export default defineConfig({
  testDir: "./test",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: "list",
  outputDir: "./test-results",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:4173",
    launchOptions: {
      args: (process.env.TRACER_CHROMIUM_FLAGS ?? "").split(/\s+/).filter(Boolean),
    },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
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
