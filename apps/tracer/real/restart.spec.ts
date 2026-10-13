/** Regresses silent input loss and false window readiness across a production systemd restart (#199). */
import { test } from "playwright/test";
import { exerciseRestart } from "./restart-fixture";

for (const unlock of [false, true]) test(`an overnight tab regains typing after systemd restart with CA ${unlock ? "unlocked" : "locked"}`, async ({ browser }) => {
  test.setTimeout(120_000);
  await exerciseRestart(browser, unlock);
});
