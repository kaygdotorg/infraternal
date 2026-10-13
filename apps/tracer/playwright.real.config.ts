/**
 * Browser specs against the real server binary (no test double): `bun x playwright test -c playwright.real.config.ts`.
 * Set `INFRATERNAL_BIN` to the server binary and build the tracer first (`bun run build`, optionally with TRACER_DIST).
 */
import { defineConfig, devices } from "playwright/test";
import { tracerEvidencePath } from "./test/evidence-path";

export default defineConfig({
  testDir: "./real",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  timeout: 120_000,
  outputDir: tracerEvidencePath("playwright-real"),
  use: { ...devices["Desktop Chrome"], ignoreHTTPSErrors: true, trace: "off", screenshot: "off", launchOptions: { args: ["--disable-renderer-backgrounding"] } },
});
