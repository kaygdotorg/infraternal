/** Independent #199 regression: typing must recover a retained browser route after a real server-only restart. */
import { test } from "playwright/test";
import { exerciseRestart } from "./restart-fixture";

for (const unlock of [false, true]) test(`typing recovers a retained browser route after a real systemd restart with CA ${unlock ? "unlocked" : "locked"}`, async ({ browser }) => {
  test.setTimeout(120_000);
  // Reuse the real passkey, CA, PTY and systemd fixture. The only modeled
  // failure is the intermediary's browser socket; this is a functional oracle.
  await exerciseRestart(browser, unlock, true);
});

for (const upstream of ["daemon", "shim"] as const) test(`typing survives a stalled ${upstream} while the server and browser stay connected`, async ({ browser }) => {
  test.setTimeout(120_000);
  await exerciseRestart(browser, false, false, upstream);
});
