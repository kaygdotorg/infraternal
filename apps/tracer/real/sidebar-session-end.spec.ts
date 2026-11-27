// SPDX-License-Identifier: AGPL-3.0-only
/** Desktop and phone sidebar actions must end the actual shell on the production server's host. */
import { devices, expect, test, type Locator, type Page } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrol, request, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";

/** Reads the shell and job PIDs from their output and verifies that both processes exist on the fixture host. */
async function startJob(page: Page, server: RealServer): Promise<number[]> {
  const input = windows(page).first().locator(".terminal-host textarea");
  await input.focus();
  await page.keyboard.type("sleep 90 & printf 'j1338-pids-%s-%s\\n' \"$$\" \"$!\"; wait");
  await page.keyboard.press("Enter");
  const pids = (): number[] => {
    const output = server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("");
    return /j1338-pids-(\d+)-(\d+)/.exec(output)?.slice(1).map(Number) ?? [];
  };
  await expect.poll(pids).toHaveLength(2);
  const owned = pids();
  expect(owned.every(alive)).toBe(true);
  return owned;
}

/** A successful signal zero proves this PID is still present without sending a signal to it. */
function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

/** Swipes left far enough to reach the in-row confirmation using real touch input. */
async function swipeToEnd(page: Page, leaf: Locator): Promise<void> {
  const box = await leaf.boundingBox();
  if (!box) throw Error("Session row has no touch target");
  const cdp = await page.context().newCDPSession(page);
  const y = box.y + box.height / 2;
  const right = box.x + box.width - 24;
  try {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: right, y }] });
    for (let step = 1; step <= 18; step += 1) {
      await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: right - (step / 18) * (box.width - 36), y }] });
    }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  } finally { await cdp.detach(); }
  const end = leaf.locator("..").locator(".ui-row-swipe-act[data-action='end']");
  await expect(leaf.locator("..").locator(".ui-row-ask").or(end).first()).toBeVisible();
  if (!(await leaf.locator("..").locator(".ui-row-ask").isVisible())) await end.tap();
}

for (const way of ["mouse", "keyboard", "touch"] as const) {
  test(`${way} ends the shell and its job after confirmation from the sidebar`, async ({ browser }) => {
    const server = await startRealServer();
    const context = await browser.newContext({
      ...(way === "touch" ? devices["iPhone 13"] : { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 }),
      ignoreHTTPSErrors: true, reducedMotion: "reduce",
    });
    try {
      const page = watchLayout(await context.newPage());
      await enrol(page, server);
      const pids = await startJob(page, server);
      const session = page.locator('#tree .bm-leaf[data-id^="s:"]');
      const sidebar = page.locator("#sidebar-toggle");
      await sidebar.click();
      await expect(page.locator('#tree[data-rows="ready"]')).toBeVisible();
      await expect(session).toHaveCount(1);
      const sid = (await session.getAttribute("data-id"))!.split("/")[1]!;
      const unrelatedId = "5adb15b1-d84e-4acb-91d7-bfcbe5b13ca0";
      expect((await request(server, context, "terminal.end", { session_id: unrelatedId })).ok).toBe(false);
      if (way === "keyboard") {
        // Closing the window detaches its shell. Ending it from the sidebar must still work.
        await sidebar.click();
        await windows(page).first().locator('[data-action="close"]').click({ force: true });
        await expect(windows(page)).toHaveCount(0);
        await sidebar.click();
        await session.press("Delete");
      } else if (way === "touch") {
        await swipeToEnd(page, session);
      } else {
        await session.click({ button: "right" });
        const menu = page.getByRole("menuitem", { name: "End session…" });
        await expect(menu).toBeVisible();
        await page.keyboard.press("Escape");
        await session.hover();
        await session.locator("..").getByRole("button", { name: /^End session / }).click();
      }
      const ask = page.locator(".ui-row-ask");
      const label = session.locator(".bm-label");
      await expect(ask.getByRole("button", { name: "Keep", exact: true })).toBeVisible();
      await expect(ask).toHaveAccessibleDescription(/closes its shell and stops programs/);
      if (way === "mouse") {
        await ask.getByRole("button", { name: "Keep", exact: true }).click();
        await expect(ask).toHaveCount(0);
        await expect(session).toBeVisible();
        expect(pids.every(alive)).toBe(true);
        await session.click({ button: "right" });
        await page.getByRole("menuitem", { name: "End session…" }).click();
        await expect(ask).toBeVisible();
      }
      expect(pids.every(alive)).toBe(true);
      const labelX = (await label.boundingBox())!.x;
      const questionX = (await ask.locator(".ui-row-ask-q").boundingBox())!.x;
      expect(Math.abs(labelX - questionX)).toBeLessThanOrEqual(0.5);
      await page.screenshot({ path: tracerEvidencePath(`sidebar-session-end-${way}.png`) });
      const started = Date.now();
      await ask.getByRole("button", { name: "End", exact: true }).click();
      await expect(session).toHaveCount(0);
      await expect.poll(() => pids.filter(alive)).toEqual([]);
      await expect(windows(page)).toHaveCount(0);
      await expect(page.getByText(/Shell was stopped by signal/)).toHaveCount(0);
      console.log(`SIDEBAR_SESSION_END ${way} confirmed_to_no_row_and_processes_ms=${Date.now() - started}`);
      expect((await request(server, context, "terminal.end", { session_id: sid })).ok).toBe(true);
    } finally {
      await context.close();
      await server.dispose();
    }
  });
}
