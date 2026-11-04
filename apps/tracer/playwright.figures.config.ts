// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Runs the capture of the docs' figures (`bun run docs:figures`, figures/capture.ts, #302).
 *
 * It is not part of the test suite (`playwright.config.ts` looks in test/ only). It builds the app's preview build into its own
 * folder with the demo dataset (TRACER_DATASET=docs: plain names, docs-dataset.ts), and serves it with the test double running the
 * same dataset behind the latency proxy the suite uses (no added delay is set, so a capture is as fast as the machine).
 */
import { defineConfig } from "playwright/test";

/** The port of the capture server; `TRACER_TEST_PORT`, default 4641. */
const port = Number(process.env.TRACER_TEST_PORT ?? "4641");
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("TRACER_TEST_PORT must be an integer TCP port");
/** The address the capture opens. */
const origin = `http://localhost:${port}`;

/** The capture setup: runs `figures/capture.ts` against a docs-dataset build and its test-double server. */
export default defineConfig({
  testDir: "./figures",
  testMatch: "capture.ts",
  fullyParallel: false,
  workers: 1,
  // A headless browser occasionally hangs on close under load; a retry takes the same picture again (the capture is deterministic).
  retries: 1,
  reporter: "list",
  use: {
    baseURL: origin,
    launchOptions: { args: ["--disable-renderer-backgrounding", "--font-render-hinting=none"] },
    trace: "off",
    screenshot: "off",
  },
  webServer: {
    command: "bun run build && python3 ../../scripts/latency_proxy.py serve-tracer",
    env: {
      TRACER_TEST_PORT: String(port),
      TRACER_DIST: "dist-figures",
      TRACER_DATASET: "docs",
      INFRATERNAL_CLUSTERS_PREVIEW: "1",
    },
    url: `${origin}/health`,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
