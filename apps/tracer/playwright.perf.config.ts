/** Runs unchanged browser speed budgets on the locked perf VM against a copied production build (#314). */
import { defineConfig } from "playwright/test";
import { hostname } from "node:os";
import base from "./playwright.config";

if (!hostname().startsWith("infraternal-perf")) throw new Error("browser performance budgets require the perf VM and perf-run");

const server = base.webServer;
if (!server || Array.isArray(server)) throw new Error("expected one tracer server fixture");

export default defineConfig({
  ...base,
  testDir: "./perf",
  // Build on a development VM and copy dist/ here; perf-run holds the measurement lock.
  webServer: {
    ...server,
    command: "python3 ../../scripts/latency_proxy.py serve-tracer",
  },
});
