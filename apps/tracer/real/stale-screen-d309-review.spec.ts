/**
 * D309 real-engine checks on the production server and real PTYs. A silent replay shows the stale-screen note when
 * the reattach changed the size (a window resized while the server restarted), and a viewer that reattaches at the
 * size it already had, such as a plain reload of an idle shell, never shows it (#257): the shell is correctly silent.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { everShown, FLOATING_NOTE, NOTE, recordNote } from "../test/stale-note-recorder";
import { pair } from "./layout-devices";

test("a silent real shell shows the pill icon after a reattach that changed its size, and fresh output clears it", async ({ browser }) => {
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
    const note = f.page.locator(NOTE);
    await expect(note).toHaveAttribute("aria-label", "Screen may be out of date", { timeout: 10_000 });
    await expect(f.page.locator(FLOATING_NOTE)).toHaveCount(0);
    await f.page.screenshot({ path: tracerEvidencePath("stale-review-real-pty-note.png") });
    await host.locator("textarea").focus();
    await f.page.keyboard.press("Control+C");
    await expect(note).toHaveCount(0, { timeout: 10_000 });
  } finally { await f.dispose(); }
});

test("a reload of an idle shell at an unchanged size never shows the pill icon", async ({ browser }) => {
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
    const textarea = f.page.locator('.cl[data-view="console"] .terminal-host textarea');
    // The first reload settles the shell at this viewer's size; the second one is the unchanged-size reattach.
    await f.page.reload();
    await expect(textarea).toHaveCount(1, { timeout: 15_000 });
    await f.page.waitForTimeout(2_000);
    await recordNote(f.page);
    await f.page.reload();
    await expect(textarea).toHaveCount(1, { timeout: 15_000 });
    // Past the longest wait the client allows (1.5 s), so a late note would have shown.
    await f.page.waitForTimeout(3_000);
    expect(await everShown(f.page)).toBe(0);
    await expect(f.page.locator(NOTE)).toHaveCount(0);
    // Every reload reattached to the one shell; a fresh shell would have nothing to be out of date.
    expect(new Set(f.server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat())).size).toBe(1);
    await f.page.screenshot({ path: tracerEvidencePath("stale-review-real-pty-reload-idle.png") });
  } finally { await f.dispose(); }
});
