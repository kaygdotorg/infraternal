/**
 * D309 real-engine checks on the production server and real PTYs. A silent replay shows the stale-screen note when
 * the reattach changed the size (a window resized while the server restarted), and a viewer that reattaches at the
 * size it already had, such as a plain reload of an idle shell, never shows it (#257): the shell is correctly silent.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { everShown, recordNote } from "../test/stale-note-recorder";
import { pair } from "./layout-devices";

test("a silent real shell shows the note after a reattach that changed its size, and fresh output clears it", async ({ browser }) => {
  test.setTimeout(90_000);
  const f = await pair(browser);
  try {
    const host = f.page.locator('.cl[data-view="console"] .terminal-host');
    await host.click();
    await host.locator("textarea").focus();
    await f.page.keyboard.type("sleep 30", { delay: 10 });
    await f.page.keyboard.press("Enter");
    await expect.poll(() => f.server.bridges.flatMap((bridge) => [...bridge.output.values()]).join(""), { timeout: 10_000 }).toContain("sleep 30");
    // The desktop window changes size while the server is away, so its reattach resizes the shell; `sleep` never redraws.
    // (The phone shares the session: whether it also sees the note depends on which viewer reattaches first, so it is not asserted.)
    await f.server.restart(async () => {
      await f.page.setViewportSize({ width: 1100, height: 700 });
      await f.page.waitForTimeout(500);
    });
    const note = f.page.locator('.ui-terminal-note[data-shown]');
    await expect(note).toHaveText("screen may be out of date", { timeout: 10_000 });
    await f.page.screenshot({ path: tracerEvidencePath("stale-review-real-pty-note.png") });
    await host.locator("textarea").focus();
    await f.page.keyboard.press("Control+C");
    await expect(note).toHaveCount(0, { timeout: 10_000 });
  } finally { await f.dispose(); }
});

test("a reload of an idle shell at an unchanged size never shows the note", async ({ browser }) => {
  test.setTimeout(90_000);
  const f = await pair(browser);
  try {
    // Only this viewer's size counts here; the phone would resize the shared shell back on its own reattach.
    await f.phone.close();
    const host = f.page.locator('.cl[data-view="console"] .terminal-host');
    await host.click();
    await host.locator("textarea").focus();
    await f.page.keyboard.type("echo idle-ready", { delay: 10 });
    await f.page.keyboard.press("Enter");
    await expect.poll(() => f.server.bridges.flatMap((bridge) => [...bridge.output.values()]).join(""), { timeout: 10_000 }).toContain("idle-ready");
    // The first reload settles the shell at this viewer's size; the second one is the unchanged-size case.
    await f.page.reload();
    await expect(f.page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(1, { timeout: 15_000 });
    await expect.poll(() => f.page.evaluate(() => document.querySelector('.cl[data-view="console"] .terminal-host canvas') !== null), { timeout: 15_000 }).toBe(true);
    await f.page.waitForTimeout(2_000);
    await f.page.reload();
    await recordNote(f.page);
    await expect(f.page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(1, { timeout: 15_000 });
    // Past the longest wait the client allows (1.5 s), so a late note would have shown.
    await f.page.waitForTimeout(3_000);
    expect(await everShown(f.page)).toBe(0);
    await expect(f.page.locator('.ui-terminal-note[data-shown]')).toHaveCount(0);
    await f.page.screenshot({ path: tracerEvidencePath("stale-review-real-pty-reload-idle.png") });
  } finally { await f.dispose(); }
});
