/** Measures the shared real restart fixture only in an isolated perf-VM mount namespace (#199, D259). */
import { readFile } from "node:fs/promises";
import { cpus, hostname, totalmem } from "node:os";
import { chromium } from "playwright";
import { exerciseRestart } from "./restart-fixture";
import { requirePrivateRuntime } from "./restart-namespace";

if (process.env.RESTART_MEASURE !== "1" || process.env.REAL_ROOT_NAMESPACE !== "1") {
  throw new Error("restart measurements require the perf-VM driver and its private mount namespace");
}
await requirePrivateRuntime();
console.log(`ENVIRONMENT machine=${hostname()} cores=${cpus().length} memory_bytes=${totalmem()} load=${(await readFile("/proc/loadavg", "utf8")).trim()} sessions=${process.env.RESTART_SESSIONS}`);
// The private TLS front has a fixture certificate, unlike production's trusted certificate.
// Trust it before the first handshake so certificate rejection/retry is not measured as recovery.
const browser = await chromium.launch({ args: ["--disable-renderer-backgrounding", "--no-sandbox", "--ignore-certificate-errors"] });
try {
  const mode = process.env.RESTART_MODE ?? "retained";
  if (!["retained", "closed", "daemon", "shim"].includes(mode)) throw new Error("invalid restart measurement mode");
  const cases = process.env.RESTART_UNLOCK === undefined ? [false, true] : [process.env.RESTART_UNLOCK === "1"];
  for (const unlock of cases) await exerciseRestart(browser, unlock, mode === "retained", mode === "daemon" || mode === "shim" ? mode : undefined);
} finally { await browser.close(); }
