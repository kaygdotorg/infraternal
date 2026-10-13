/** Independent #199 regression: typing must recover a retained browser route after a real server-only restart. */
import { test } from "playwright/test";
import { exerciseRestart } from "./restart-fixture";

test("typing recovers a retained browser route after a real systemd restart", async ({ browser }) => {
  test.setTimeout(120_000);
  // Reuse the real passkey, CA, PTY and systemd fixture. The only modeled
  // failure is the intermediary's browser socket; this is a functional oracle.
  await exerciseRestart(browser, false, true);
});
