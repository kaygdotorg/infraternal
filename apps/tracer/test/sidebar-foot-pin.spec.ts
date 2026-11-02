/**
 * The sidebar's account pill stays pinned to the sidebar's bottom (#259).
 *
 * The owner saw the pill (avatar, name, gear) drift up under the Settings group while the panel itself still
 * reached the bottom of the window. The pill's bottom gap (the sidebar's bottom edge minus the pill's bottom
 * edge) is sampled every frame, and must be the same few pixels in every state: tree expanded and collapsed,
 * groups of different lengths, a tall 1773x2000 window and a 1440x900 one, an inbox card that came and went,
 * and a tab that was hidden and shown again. No sample may differ from the first by more than half a pixel.
 */
import { expect, test, type Page } from "playwright/test";

const SIZES = [{ width: 1440, height: 900 }, { width: 1773, height: 2000 }] as const;

async function open(page: Page, query: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=ink&${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(500);
}

/** The pill's bottom gap, sampled on `frames` animation frames; also the pill's own height for a sanity check. */
async function gaps(page: Page, frames = 45): Promise<number[]> {
  return page.evaluate((count) => new Promise<number[]>((done) => {
    const out: number[] = [];
    const step = (): void => {
      const sidebar = document.querySelector("#sidebar")!.getBoundingClientRect();
      const foot = document.querySelector(".ui-sidebar-foot")!.getBoundingClientRect();
      out.push(Math.round((sidebar.bottom - foot.bottom) * 100) / 100);
      if (out.length >= count) done(out); else requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }), frames);
}

async function expectPinned(page: Page, label: string, reference: number): Promise<void> {
  const samples = await gaps(page);
  for (const gap of samples) expect(Math.abs(gap - reference), `${label}: ${samples.join(",")}`).toBeLessThanOrEqual(0.5);
}

for (const size of SIZES) {
  test(`the pill stays at the bottom: tree open and collapsed, inbox came and went (${size.width}x${size.height})`, async ({ page }) => {
    await page.setViewportSize(size);
    await open(page, "ca=locked");
    const reference = (await gaps(page, 1))[0]!;
    // Pinned means a few pixels (the sidebar's own padding), never a tree's height.
    expect(reference).toBeLessThanOrEqual(12);
    await expectPinned(page, "initial", reference);

    // The inbox card appears (the toast is dismissed), is expanded, and leaves again when unlocked.
    await page.locator(".ui-toast:not([hidden])").getByRole("button", { name: "Dismiss" }).click({ timeout: 8000 });
    await expect(page.locator(".ui-inbox:not([hidden])")).toBeVisible();
    await page.waitForTimeout(400);
    await expectPinned(page, "inbox card shown", reference);
    await page.locator(".ui-inbox:not([hidden])").getByRole("button", { name: "Unlock host connections" }).click();
    await page.locator(".ui-inbox:not([hidden])").getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(page.locator(".ui-inbox:not([hidden])")).toHaveCount(0);
    await page.waitForTimeout(400);
    await expectPinned(page, "inbox card gone", reference);

    // Every group collapsed, then every group open again.
    const heads = page.locator("#tree .bm-head");
    const count = await heads.count();
    for (let i = 0; i < count; i++) if ((await heads.nth(i).getAttribute("aria-expanded")) === "true") await heads.nth(i).click();
    await page.waitForTimeout(500);
    await expectPinned(page, "all groups collapsed", reference);
    for (let i = 0; i < count; i++) if ((await heads.nth(i).getAttribute("aria-expanded")) === "false") await heads.nth(i).click();
    await page.waitForTimeout(500);
    await expectPinned(page, "all groups open", reference);

    // Idle for a while, hidden and shown again.
    await page.waitForTimeout(3000);
    await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true }); document.dispatchEvent(new Event("visibilitychange")); });
    await page.waitForTimeout(500);
    await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true }); document.dispatchEvent(new Event("visibilitychange")); });
    await page.waitForTimeout(1500);
    await expectPinned(page, "after idle", reference);
  });
}

// Review screenshots of the pinned pill in the state that used to break it (`RENAME_CAPTURES=1`, external evidence directory).
for (const [name, size, theme, touch] of [["desktop-ink", { width: 1773, height: 2000 }, "ink", false], ["desktop-paper", { width: 1440, height: 900 }, "paper", false], ["phone-ink", { width: 393, height: 852 }, "ink", true]] as const) {
  test(`capture: the pill after the inbox card has gone (${name})`, async ({ browser }) => {
    test.skip(!process.env.RENAME_CAPTURES, "review captures only");
    const context = await browser.newContext({ viewport: size, deviceScaleFactor: touch ? 3 : 1, ...(touch ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&ca=locked`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.locator("#sidebar-toggle").click();
    await page.locator(".ui-toast:not([hidden])").getByRole("button", { name: "Dismiss" }).click({ timeout: 8000 });
    await page.locator(".ui-inbox:not([hidden])").getByRole("button", { name: "Unlock host connections" }).click();
    await page.locator(".ui-inbox:not([hidden])").getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(page.locator(".ui-inbox:not([hidden])")).toHaveCount(0);
    await page.waitForTimeout(800);
    const { tracerEvidencePath } = await import("./evidence-path");
    await page.screenshot({ path: tracerEvidencePath("sidebar-pill-259", `pill-${name}.png`) });
    await context.close();
  });
}
