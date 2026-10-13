/** Measures the shared real restart fixture only in an isolated perf-VM mount namespace (#199, D259). */
import { readFile, readlink } from "node:fs/promises";
import { cpus, hostname, totalmem } from "node:os";
import { chromium } from "playwright";
import { exerciseRestart } from "./restart-fixture";

if (process.env.RESTART_MEASURE !== "1" || process.env.REAL_ROOT_NAMESPACE !== "1"
  || await readlink("/proc/self/ns/mnt") === await readlink("/proc/1/ns/mnt")) {
  throw new Error("restart measurements require the perf-VM driver and its private mount namespace");
}
console.log(`ENVIRONMENT machine=${hostname()} cores=${cpus().length} memory_bytes=${totalmem()} load=${(await readFile("/proc/loadavg", "utf8")).trim()} sessions=${process.env.RESTART_SESSIONS}`);
const browser = await chromium.launch({ args: ["--disable-renderer-backgrounding", "--no-sandbox"] });
try {
  const mode = process.env.RESTART_MODE ?? "retained";
  if (!["retained", "closed", "daemon", "shim"].includes(mode)) throw new Error("invalid restart measurement mode");
  const cases = process.env.RESTART_UNLOCK === undefined ? [false, true] : [process.env.RESTART_UNLOCK === "1"];
  for (const unlock of cases) await exerciseRestart(browser, unlock, mode === "retained", mode === "daemon" || mode === "shim" ? mode : undefined);
} finally { await browser.close(); }
