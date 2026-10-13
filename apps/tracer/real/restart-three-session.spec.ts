/** Verifies recovery and input isolation for three visible real PTYs on one production browser route (#199, D265). */
import { test } from "playwright/test";
import { exerciseRestart } from "./restart-fixture";

for (const retained of [false, true]) for (const unlock of [false, true])
  test(`three windows resume after systemd restart: ${retained ? "retained" : "closed"} route, CA ${unlock ? "unlocked" : "locked"}`, async ({ browser }) => {
    await exerciseRestart(browser, unlock, retained, undefined, 3);
  });

for (const upstream of ["daemon", "shim"] as const)
  test(`three windows retain isolated input after a stalled ${upstream}`, async ({ browser }) => {
    await exerciseRestart(browser, false, false, upstream, 3);
  });
