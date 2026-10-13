/**
 * The toolbar's lock toggles (TASTE: lock icons are the thing plus a lock, #164): off, each shows the plain icon of what it
 * locks (the canvas, the terminal); on, the same icon with the shared lock badge and nothing else changed. Phone toolbar at
 * 393x852 in ink and paper, both toggles off and on, with 3x crops of the capsule.
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("lock-icons");

for (const theme of ["ink", "paper"] as const) {
  test(`phone toolbar ${theme}: canvas lock and input lock are the plain icon off and the badged icon on`, async ({ browser }) => {
    test.setTimeout(120_000);
    await mkdir(captures, { recursive: true });
    const context = await browser.newContext({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
    const page = await context.newPage();
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
    await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
    await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
    await page.waitForTimeout(1800);
    const shape = (id: string) => page.evaluate((cv) => {
      const svg = document.querySelector(`[data-cv='${cv}'] svg`)!;
      return { badge: svg.querySelector("rect[fill='currentColor']") !== null, masked: svg.querySelector("g[mask]") !== null, pressed: document.querySelector(`[data-cv='${cv}']`)!.getAttribute("aria-pressed"), shapes: svg.querySelectorAll("rect, path, circle").length };
    }, id);
    // A focused terminal brings the key row; one snap swipe down reveals the canvas row again (as a finger does).
    const cdp = await context.newCDPSession(page);
    const touch = (type: "touchStart" | "touchMove" | "touchEnd", y: number, x: number) => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y, id: 0 }] });
    const showCanvasRow = async () => {
      if (await page.evaluate(() => document.querySelector("#terminal-screen")!.getAttribute("data-row")) === "canvas") return;
      const t = (await page.locator(".keytray").boundingBox())!;
      await touch("touchStart", t.y + 12, t.x + 100);
      for (let i = 1; i <= 6; i++) { await touch("touchMove", t.y + 12 + i * 6, t.x + 100); await page.waitForTimeout(30); }
      await touch("touchEnd", t.y + 48, t.x + 100);
      await expect.poll(() => page.evaluate(() => document.querySelector("#terminal-screen")!.getAttribute("data-row"))).toBe("canvas");
      await page.waitForTimeout(700);
    };
    const shot = async (name: string) => {
      await showCanvasRow();
      const tray = (await page.locator(".keytray").boundingBox())!;
      await page.screenshot({ path: `${captures}/${name}-${theme}.png`, clip: { x: tray.x - 4, y: tray.y - 4, width: tray.width + 8, height: tray.height + 8 } });
    };
    const knockoutHeld = () => page.evaluate(() => document.querySelectorAll("#ui-lock-knockout").length);

    // The canvas lock is on at load (snapped by default): canvas icon with the badge. Input lock: off, the plain terminal.
    let canvas = await shape("canvas-lock"), input = await shape("input-lock");
    expect(canvas).toMatchObject({ badge: true, masked: true, pressed: "true" });
    expect(input).toMatchObject({ badge: false, masked: false, pressed: "false" });
    await shot("canvas-on-input-off");

    // Canvas lock off: the plain canvas icon.
    await page.evaluate(() => document.querySelector<HTMLElement>("[data-cv='canvas-lock']")!.click());
    await page.waitForTimeout(500);
    canvas = await shape("canvas-lock");
    expect(canvas).toMatchObject({ badge: false, masked: false, pressed: "false" });
    await shot("canvas-off-input-off");

    // Input lock on (a terminal active): the terminal icon with the badge.
    await page.locator("[data-view='console'] .ui-window").first().click({ position: { x: 150, y: 150 } });
    await page.waitForTimeout(400);
    await page.evaluate(() => document.querySelector<HTMLElement>("[data-cv='input-lock']")!.click());
    await page.waitForTimeout(500);
    await showCanvasRow();
    input = await shape("input-lock");
    expect(input).toMatchObject({ badge: true, masked: true, pressed: "true" });
    await shot("canvas-off-input-on");
    expect(await knockoutHeld(), "one shared knock-out in the document").toBe(1);

    // Input lock off again: back to the plain icon.
    await page.locator("[data-cv='input-lock']").tap();
    await page.waitForTimeout(500);
    expect(await shape("input-lock")).toMatchObject({ badge: false, masked: false, pressed: "false" });
    await context.close();
  });
}
