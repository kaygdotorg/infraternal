/**
 * Review captures of the sidebar's row menu, swipes, in-row question, rename field, hover pill and the access-level consent
 * (#242, #215), taken from a production build of the tracer: desktop 1440×900 at DPR 2 and phone 393×852 at DPR 3, ink and
 * paper. Off unless `ROW_CAPTURES=1`; the images go to the external evidence directory, never into the checkout.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

test.skip(!process.env.ROW_CAPTURES, "review captures are taken on request");

const OUT = tracerEvidencePath("row-captures");
const shoot = async (page: Page, name: string, clip?: { x: number; y: number; width: number; height: number }): Promise<void> => {
  mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: resolve(OUT, `${name}.png`), ...(clip ? { clip } : {}) });
};
/** The sidebar and what hangs from it, cropped to the left part of the screen. */
const sidebarClip = async (page: Page): Promise<{ x: number; y: number; width: number; height: number }> => {
  const b = (await page.locator("#sidebar").boundingBox())!;
  return { x: Math.max(0, b.x - 8), y: Math.max(0, b.y), width: Math.min(b.width + 340, page.viewportSize()!.width - Math.max(0, b.x - 8)), height: Math.min(b.height, page.viewportSize()!.height) };
};
const ID = "s:build-01/deploy";
const leaf = (page: Page, id = ID) => page.locator(`#tree [data-id="${id}"]`);

async function open(page: Page, theme: string, privilege = false): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none&removal=1${privilege ? "&privilege=sudo" : ""}`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(900);
}
const openSidebar = async (page: Page): Promise<void> => { await page.locator("#sidebar-toggle").click(); await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); await expect(leaf(page)).toBeVisible(); await page.waitForTimeout(900); };

for (const theme of ["ink", "paper"]) {
  test.describe(`desktop 1440×900 @2x, ${theme}`, () => {
    test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    test("sidebar rows", async ({ page }) => {
      await open(page, theme);
      await openSidebar(page);
      const hover = leaf(page, "s:build-01/journal");
      const hb = (await hover.boundingBox())!;
      await page.mouse.move(hb.x + 60, hb.y + hb.height / 2);
      await page.waitForTimeout(300);
      await shoot(page, `desktop-${theme}-hover-pill`, await sidebarClip(page));
      await leaf(page).click({ button: "right" });
      await expect(page.locator(".ui-window-menu")).toBeVisible();
      await page.waitForTimeout(400);
      await shoot(page, `desktop-${theme}-session-menu`, await sidebarClip(page));
      await page.locator(".ui-window-menu-item", { hasText: "End session" }).click();
      await expect(page.locator(".ui-row-ask")).toBeVisible();
      await page.waitForTimeout(400);
      await shoot(page, `desktop-${theme}-end-asks-in-row`, await sidebarClip(page));
      await page.keyboard.press("Escape");
      await leaf(page).dblclick();
      await expect(page.locator(".ui-inline-rename")).toBeVisible();
      await page.waitForTimeout(300);
      await shoot(page, `desktop-${theme}-rename-field`, await sidebarClip(page));
      await page.keyboard.press("Escape");
      await page.locator('#tree li.bm-subhead[data-id="h:edge-arm"]').click({ button: "right" });
      await expect(page.locator(".ui-window-menu")).toBeVisible();
      await page.waitForTimeout(400);
      await shoot(page, `desktop-${theme}-host-menu`, await sidebarClip(page));
    });
    test("access level consent", async ({ page }) => {
      await open(page, theme, true);
      await page.locator(".ui-window-pill").first().click();
      await expect(page.locator(".canvas-popover")).toBeVisible();
      await page.waitForTimeout(500);
      await shoot(page, `desktop-${theme}-access-level-limited`);
      await page.locator(".canvas-popover .ui-kv-row", { hasText: "Access level" }).locator(".ui-kv-press, .ui-kv-cell").last().click();
      await expect(page.locator(".cl-pv[data-open]")).toBeVisible();
      await page.waitForTimeout(600);
      await shoot(page, `desktop-${theme}-consent`);
      await page.locator(".cl-pv .ui-confirm-yes").click();
      await page.waitForTimeout(700);
      await shoot(page, `desktop-${theme}-consent-password`);
    });
  });
  test.describe(`phone 393×852 @3x, ${theme}`, () => {
    test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
    test("sidebar rows", async ({ page }) => {
      await open(page, theme);
      await openSidebar(page);
      const cdp = await page.context().newCDPSession(page);
      const b = (await leaf(page).boundingBox())!;
      const y = b.y + b.height / 2;
      const send = (type: "touchStart" | "touchMove" | "touchEnd", x = 0): Promise<unknown> => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y }] });
      // Long press: the menu.
      await send("touchStart", b.x + 80);
      await page.waitForTimeout(700);
      await send("touchEnd");
      await expect(page.locator(".ui-window-menu")).toBeVisible();
      await page.waitForTimeout(400);
      await shoot(page, `phone-${theme}-session-menu`);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(300);
      // A short left swipe: End revealed.
      await send("touchStart", b.x + b.width - 30);
      for (let i = 1; i <= 14; i += 1) { await send("touchMove", b.x + b.width - 30 - i * 8); await page.waitForTimeout(8); }
      await send("touchEnd");
      await page.waitForTimeout(700);
      await shoot(page, `phone-${theme}-swipe-end-revealed`);
      await page.locator("#tree .ui-row-swipe-act[data-action='end']").tap();
      await expect(page.locator(".ui-row-ask")).toBeVisible();
      await page.waitForTimeout(1000);
      await shoot(page, `phone-${theme}-end-asks-in-row`);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(300);
      // A short right swipe: Open beside revealed.
      await send("touchStart", b.x + 40);
      for (let i = 1; i <= 14; i += 1) { await send("touchMove", b.x + 40 + i * 6); await page.waitForTimeout(8); }
      await send("touchEnd");
      await page.waitForTimeout(700);
      await shoot(page, `phone-${theme}-swipe-beside-revealed`);
    });
    test("access level consent", async ({ page }) => {
      await open(page, theme, true);
      await page.locator(".ui-window-pill").first().tap();
      await expect(page.locator(".canvas-popover")).toBeVisible();
      await page.waitForTimeout(500);
      await page.locator(".canvas-popover .ui-kv-row", { hasText: "Access level" }).locator(".ui-kv-press, .ui-kv-cell").last().tap();
      await expect(page.locator(".cl-pv[data-open]")).toBeVisible();
      await page.waitForTimeout(600);
      await shoot(page, `phone-${theme}-consent`);
    });
  });
}
