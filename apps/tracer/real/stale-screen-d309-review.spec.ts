/**
 * D309 real-engine check: a silent real PTY replay shows the stale-screen note after the production server reconnects.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { pair } from "./layout-devices";

test("several real viewers show the silent replay note and clear it on fresh shell output", async ({ browser }) => {
  test.setTimeout(90_000);
  const f = await pair(browser);
  try {
    const host = f.page.locator('.cl[data-view="console"] .terminal-host');
    await host.click();
    await host.locator("textarea").focus();
    await f.page.keyboard.type("sleep 30", { delay: 10 });
    await f.page.keyboard.press("Enter");
    await expect.poll(() => f.server.bridges.flatMap((bridge) => [...bridge.output.values()]).join(""), { timeout: 10_000 }).toContain("sleep 30");
    await f.server.restart();
    const note = f.page.locator('.ui-terminal-note[data-shown]');
    const phoneNote = f.mobile.locator('.ui-terminal-note[data-shown]');
    await expect(note).toHaveText("screen may be out of date", { timeout: 10_000 });
    await expect(phoneNote).toHaveText("screen may be out of date", { timeout: 10_000 });
    await f.page.screenshot({ path: tracerEvidencePath("stale-review-real-pty-note.png") });
    await f.mobile.screenshot({ path: tracerEvidencePath("stale-review-real-pty-phone-note.png") });
    await host.locator("textarea").focus();
    await f.page.keyboard.press("Control+C");
    await expect(note).toHaveCount(0, { timeout: 10_000 });
    await expect(phoneNote).toHaveCount(0, { timeout: 10_000 });
  } finally { await f.dispose(); }
});
