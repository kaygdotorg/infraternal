/**
 * Browser specs against the real server binary (no test double): `bun x playwright test -c playwright.real.config.ts`.
 * Set `INFRATERNAL_BIN` to the server binary and build the tracer first (`bun run build`, optionally with TRACER_DIST).
 */
import { defineConfig, devices } from "playwright/test";
import { tracerEvidencePath } from "./test/evidence-path";

// The owner demo binds to a private interface while retaining a DNS name for passkey setup.
const demoHost = process.env.TERMINAL_LINKS_DEMO_HOST;
const demoAddress = process.env.TERMINAL_LINKS_DEMO_ADDRESS;
const browserName = process.env.TRACER_TEST_BROWSER ?? "chromium";
if (browserName !== "chromium" && browserName !== "webkit" && browserName !== "firefox") throw Error("unsupported production test browser");

export default defineConfig({
  testDir: "./real",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  timeout: 120_000,
  outputDir: tracerEvidencePath("playwright-real"),
  use: {
    ...devices["Desktop Chrome"],
    browserName,
    ignoreHTTPSErrors: true,
    trace: "off",
    screenshot: "off",
    launchOptions: {
      args: browserName === "chromium" ? [
        "--disable-renderer-backgrounding",
        // The private fixture certificate also covers service-worker fetches.
        "--ignore-certificate-errors",
        ...(demoHost && demoAddress ? [`--host-resolver-rules=MAP ${demoHost} ${demoAddress}`] : []),
      ] : [],
    },
  },
});
