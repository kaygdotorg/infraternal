/** Runs browser checks against the production tracer build through the test latency proxy [#55, D122, D130]. */
import { defineConfig, devices } from "playwright/test";
import { tracerEvidencePath } from "./test/evidence-path";

/** The port of the test server; `TRACER_TEST_PORT`, default 4621. */
const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("TRACER_TEST_PORT must be an integer TCP port");
}
/** The pixel ratio of the test browser; `TRACER_TEST_DPR`, 1, 2 or 3. */
const deviceScaleFactor = Number(process.env.TRACER_TEST_DPR ?? "1");
if (![1, 2, 3].includes(deviceScaleFactor)) {
  throw new Error("TRACER_TEST_DPR must be 1, 2, or 3");
}
/** Set to `chrome` to run app-window checks in a branded Chrome instead of the bundled Chromium. */
const appWindowBrowser = process.env.TRACER_APPWIN_BROWSER;
if (appWindowBrowser !== undefined && appWindowBrowser !== "chrome") {
  throw new Error("TRACER_APPWIN_BROWSER must be unset or chrome");
}
/** A path to a Chrome binary to use with `TRACER_APPWIN_BROWSER=chrome`. */
const appWindowChromeExecutable = process.env.TRACER_CHROME_EXECUTABLE;
if (appWindowChromeExecutable !== undefined && appWindowBrowser !== "chrome") {
  throw new Error("TRACER_CHROME_EXECUTABLE requires TRACER_APPWIN_BROWSER=chrome");
}
// The evidence root is named after the process id (evidence-path.ts), and a worker is another process than this config.
// Export the root so specs resolve the same directory the test server writes its reports to; otherwise a spec that reads
// a server-written file (perf-hud's incident file) looks in a directory that does not exist.
process.env.INFRATERNAL_EVIDENCE_DIR ??= tracerEvidencePath(".");
// Browser reports and frame incidents stay outside the checkout.
const perfDir = process.env.INFRATERNAL_PERF_DIR ?? tracerEvidencePath("perf");
/** The address the tests open. */
const origin = `http://localhost:${port}`;

export default defineConfig({
  testDir: "./test",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  // All workers share one auth/terminal test-double process and its owner state.
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  // These are functional checks, not a timing gate (speed is measured on the perf VM). Several specs open pages with 20-45 s
  // helper waits and one runs three scenes of 8-12 s each, so the 30 s default made a loaded build host fail them for being slow.
  timeout: 90_000,
  reporter: "list",
  outputDir: tracerEvidencePath("playwright"),
  use: {
    ...devices["Desktop Chrome"],
    deviceScaleFactor,
    baseURL: origin,
    launchOptions: {
      // Keep a headless visible-surface probe on the renderer's foreground frame cadence.
      ...(appWindowBrowser === "chrome"
        ? appWindowChromeExecutable === undefined ? { channel: "chrome" } : { executablePath: appWindowChromeExecutable }
        : {}),
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
    command: "bun run build && python3 ../../scripts/latency_proxy.py serve-tracer",
    env: { TRACER_TEST_PORT: String(port), INFRATERNAL_CLUSTERS_PREVIEW: "1", INFRATERNAL_PERF_DIR: perfDir },
    url: `${origin}/health`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
