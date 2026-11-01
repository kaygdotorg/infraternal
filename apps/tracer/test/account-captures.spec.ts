/**
 * Review captures of the person's card (D283, #224): each state at 1440 x 900 (DPR 2) and 393 x 852 (DPR 3), in ink and
 * paper, and a short video of the card growing out of the pill and the "Logs in as" pane opening in the worst case.
 * Screenshots land in the external evidence directory (INFRATERNAL_EVIDENCE_DIR); the assertions only prove that each
 * state was reached, and nobody judges the pictures here.
 */
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("account-card");
const SIZES = [
  ["desktop", { width: 1440, height: 900 }, 2],
  ["phone", { width: 393, height: 852 }, 3],
] as const;

async function open(context: BrowserContext, theme: string, data: string, phone: boolean): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=3&account=1&bg=none&theme=${theme}&data=${data}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.locator("#sidebar-toggle").click();
  await page.locator(".ui-sidebar-user").click();
  await expect(page.locator('.ac[data-open="true"]')).toBeVisible({ timeout: 8000 });
  await page.waitForTimeout(600);
  void phone;
  return page;
}

const scenario = async (page: Page, id: string): Promise<void> => {
  await page.evaluate((action) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action, source: "keyboard" } })), `proto:acct:s:${id}`);
  await page.waitForTimeout(600);
};

for (const [name, viewport, scale] of SIZES) {
  for (const theme of ["ink", "paper"]) {
    test.describe(`${name} ${theme}`, () => {
      test.setTimeout(240_000);

      test("the card: healthy, each concern, the empty and the one set", async ({ browser }) => {
        const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
        const page = await open(context, theme, "demo", name === "phone");
        await page.screenshot({ path: resolve(OUT, `card-healthy-${name}-${theme}.png`) });
        for (const id of ["recovery", "recovery-stale", "recovery-none", "one-passkey", "long"]) {
          await scenario(page, id);
          await page.screenshot({ path: resolve(OUT, `card-${id}-${name}-${theme}.png`) });
        }
        await context.close();
        for (const data of ["empty", "one"]) {
          const c = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
          const p = await open(c, theme, data, name === "phone");
          await p.screenshot({ path: resolve(OUT, `card-data-${data}-${name}-${theme}.png`) });
          await c.close();
        }
      });

      test("Logs in as: the demo set and the worst case", async ({ browser }) => {
        for (const data of ["demo", "worst"]) {
          const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
          const page = await open(context, theme, data, name === "phone");
          await page.locator(".ac .ui-kv-row", { hasText: "Logs in as" }).locator(".ui-kv-value").click();
          await expect(page.locator(".ac-pane[data-open]")).toBeVisible();
          await page.waitForTimeout(700);
          await page.screenshot({ path: resolve(OUT, `logins-${data}-${name}-${theme}.png`) });
          // The pane scrolled to its end: the last account and "Access rules" are reachable and not cut.
          await page.locator(".ac-body").evaluate((n) => { n.scrollTop = n.scrollHeight; });
          await page.waitForTimeout(400);
          await page.screenshot({ path: resolve(OUT, `logins-${data}-end-${name}-${theme}.png`) });
          await context.close();
        }
      });
    });
  }

  test(`video: the card grows out of the pill and the pane opens (${name})`, async ({ browser }) => {
    test.setTimeout(240_000);
    const context = await browser.newContext({ viewport, deviceScaleFactor: 1, recordVideo: { dir: resolve(OUT, `video-${name}`), size: viewport }, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    await page.goto("/?mock=1&proto=clusters&scene=3&account=1&bg=none&theme=ink&data=worst");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    await page.locator("#sidebar-toggle").click();
    await page.waitForTimeout(700);
    await page.locator(".ui-sidebar-user").click();
    await expect(page.locator('.ac[data-open="true"]')).toBeVisible();
    await page.waitForTimeout(1200);
    await page.locator(".ac .ui-kv-row", { hasText: "Logs in as" }).locator(".ui-kv-value").click();
    await page.waitForTimeout(1500);
    await page.locator(".ac-body").evaluate((n) => n.scrollTo({ top: n.scrollHeight, behavior: "smooth" }));
    await page.waitForTimeout(1800);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(500);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(900);
    await context.close();
  });
}
