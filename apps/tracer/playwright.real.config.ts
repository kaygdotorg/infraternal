/**
 * Browser specs against the real server binary (no test double): `bun x playwright test -c playwright.real.config.ts`.
 * Set `INFRATERNAL_BIN` to the server binary and build the tracer first (`bun run build`, optionally with TRACER_DIST).
 * Set `TRACER_BROWSER_WS_ENDPOINT_FILE` to measure frame work on a loopback Playwright browser hosted separately.
 */
import { defineConfig, devices } from "playwright/test";
import { readFileSync } from "node:fs";
import { tracerEvidencePath } from "./test/evidence-path";

// The owner demo binds to a private interface while retaining a DNS name for passkey setup.
const demoHost = process.env.TERMINAL_LINKS_DEMO_HOST;
const demoAddress = process.env.TERMINAL_LINKS_DEMO_ADDRESS;
const browserName = process.env.TRACER_TEST_BROWSER ?? "chromium";
if (browserName !== "chromium" && browserName !== "webkit" && browserName !== "firefox") throw Error("unsupported production test browser");
// An isolated browser host lets frame measurements separate renderer work from server-host scheduling noise.
/** Optional private endpoint file for the remote Playwright browser. */
const browserEndpointFile = process.env.TRACER_BROWSER_WS_ENDPOINT_FILE;
/** Connection settings read from the endpoint file without logging its secret URL. */
const connectOptions = browserEndpointFile === undefined ? undefined : (() => {
  let endpointText: string;
  try { endpointText = readFileSync(browserEndpointFile, "utf8").trim(); }
  catch { throw new Error("TRACER_BROWSER_WS_ENDPOINT_FILE must name a readable Playwright endpoint file"); }
  let endpoint: URL;
  try { endpoint = new URL(endpointText); }
  catch { throw new Error("TRACER_BROWSER_WS_ENDPOINT_FILE must contain a loopback WebSocket endpoint"); }
  if ((endpoint.protocol !== "ws:" && endpoint.protocol !== "wss:") || !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname)) {
    throw new Error("TRACER_BROWSER_WS_ENDPOINT_FILE must contain a loopback WebSocket endpoint");
  }
  return { wsEndpoint: endpointText };
})();

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
    ...(connectOptions ? { connectOptions } : {}),
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
