// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Review captures of Remove host as the owner placed it (D385, #486), from a production build: the machine card's two tabs and
 * the inline question at the end of the Connection tab (windows prototype), and the sidebar's machine row with its hover button,
 * a left swipe mid-gesture and revealed, and the glass confirmation card they open (clusters prototype). Desktop 1440×900 and
 * phone 393×852 at DPR 3, ink and paper. Off unless `J475B_CAPTURE=1`; it asserts only that each state is on screen. The images
 * go to the evidence directory under `removal-d385/`.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

test.skip(process.env.J475B_CAPTURE !== "1", "set J475B_CAPTURE=1 to capture");

/** The two viewports the owner reviews: desktop and phone. */
const sizes = [{ id: "desktop", width: 1440, height: 900, scale: 2, touch: false }, { id: "phone", width: 393, height: 852, scale: 3, touch: true }] as const;
/** One dark and one light theme. */
const themes = ["ink", "paper"] as const;
/** Where one capture is written. */
const out = (name: string): string => tracerEvidencePath("removal-d385", `${name}.png`);

/** Opens the first window's machine card on the windows prototype, with removal on. */
async function openCard(page: Page, theme: string): Promise<void> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=windows&bg=none&fixture=none&removal=1&theme=${theme}`);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  // sleep: the card's open animation (200 ms) settles
  await page.waitForTimeout(500);
}

for (const size of sizes) for (const theme of themes) {
  test(`machine card ${size.id} ${theme}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: theme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    try {
      await openCard(page, theme);
      const window = page.locator(".ui-window").first();
      await window.screenshot({ path: out(`${size.id}-${theme}-1-machine-tab`) });
      await page.locator(".canvas-popover .ui-tab", { hasText: "Connection" }).click();
      // sleep: a tab change or scroll settles
      await page.waitForTimeout(300);
      await page.locator(".canvas-popover-action").scrollIntoViewIfNeeded();
      // sleep: a tab change or scroll settles
      await page.waitForTimeout(300);
      await window.screenshot({ path: out(`${size.id}-${theme}-2-connection-tab-end`) });
      await page.locator(".canvas-popover-action .ui-sp-row").click();
      await expect(page.locator(".canvas-popover-ask")).toBeVisible();
      await page.locator(".canvas-popover-ask").scrollIntoViewIfNeeded();
      // sleep: a tab change or scroll settles
      await page.waitForTimeout(300);
      await window.screenshot({ path: out(`${size.id}-${theme}-3-inline-question`) });
    } finally { await context.close(); }
  });

  test(`sidebar machine row ${size.id} ${theme}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: theme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    try {
      await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none&removal=1`);
      await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
      // sleep: the mock scene settles before the camera flight
      await page.waitForTimeout(700);
      await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
      // sleep: the camera flight to the view lasts under 300 ms; margin for a loaded VM
      await page.waitForTimeout(900);
      await page.locator("#sidebar-toggle").click();
      await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
      const host = page.locator('#tree li.bm-subhead[data-id="h:edge-arm"]');
      await expect(host).toBeVisible();
      // sleep: the card's open animation settles
      await page.waitForTimeout(500);
      if (!size.touch) {
        const box = (await host.boundingBox())!;
        await page.mouse.move(box.x + 60, box.y + box.height / 2);
        // sleep: a tab change or scroll settles
        await page.waitForTimeout(300);
        await page.screenshot({ path: out(`${size.id}-${theme}-4-sidebar-hover-button`) });
        await page.locator(".cl-ha button[data-act='remove']").click();
      } else {
        const cdp = await context.newCDPSession(page);
        const b = (await host.boundingBox())!;
        const y = b.y + b.height / 2;
        const send = (type: "touchStart" | "touchMove" | "touchEnd", x = 0): Promise<unknown> => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y }] });
        await send("touchStart", b.x + b.width - 30);
        // sleep: one touch step per frame
        for (let i = 1; i <= 7; i += 1) { await send("touchMove", b.x + b.width - 30 - i * 8); await page.waitForTimeout(8); }
        await page.screenshot({ path: out(`${size.id}-${theme}-5-swipe-mid-gesture`) });
        // sleep: one touch step per frame
        for (let i = 8; i <= 14; i += 1) { await send("touchMove", b.x + b.width - 30 - i * 8); await page.waitForTimeout(8); }
        await send("touchEnd");
        // sleep: the swipe settles back to its revealed rest
        await page.waitForTimeout(700);
        await page.screenshot({ path: out(`${size.id}-${theme}-6-swipe-revealed`) });
        await page.locator("#tree .ui-row-swipe-act[data-action='remove']").tap();
      }
      await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
      // sleep: the confirmation card's entrance (under 300 ms)
      await page.waitForTimeout(450);
      await page.screenshot({ path: out(`${size.id}-${theme}-7-sidebar-confirm-card`) });
    } finally { await context.close(); }
  });
}
