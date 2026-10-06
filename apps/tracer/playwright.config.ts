/** Runs browser checks against the built tracer and its clearly marked test double. */
import { defineConfig, devices } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4173");
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("TRACER_TEST_PORT must be an integer TCP port");
}
const origin = `http://localhost:${port}`;

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
    baseURL: origin,
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
    url: `${origin}/health`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
