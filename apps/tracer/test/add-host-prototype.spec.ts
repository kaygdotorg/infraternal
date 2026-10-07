/** Exercises the mock-only add-host window: one field, quiet selection, consent, outcomes, motion. */
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4173");
const origin = `http://localhost:${port}`;

type Viewport = { width: number; height: number; touch?: boolean };
const DESKTOP: Viewport = { width: 1440, height: 900 };
const PHONE: Viewport = { width: 393, height: 852, touch: true };

async function open(browser: Browser, viewport: Viewport, theme = "ink"): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({
    baseURL: origin,
    viewport: { width: viewport.width, height: viewport.height },
    hasTouch: !!viewport.touch,
    isMobile: !!viewport.touch,
  });
  const page = await context.newPage();
  await page.goto(`${origin}/?mock=1&proto=addhost&theme=${theme}&bg=none`);
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 15_000 });
  return { context, page };
}

async function press(page: Page, viewport: Viewport, selector: string): Promise<void> {
  const target = page.locator(selector).first();
  if (viewport.touch) await target.tap();
  else await target.click();
}

test("one field filters discovered hosts and turns unknown text into a manual row", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await expect(page.locator("[role='tab']")).toHaveCount(0);
    await expect(page.getByText("Discovery sources")).toHaveCount(0);
    await expect(page.getByText("Gather extended information")).toHaveCount(0);
    const input = page.locator(".ah-input");
    await input.fill("edge");
    await expect(page.locator(".ah-row:not([hidden])")).toHaveCount(1);
    await expect(page.locator(".ah-manual")).toBeHidden();
    await input.fill("root@pve02");
    await expect(page.locator(".ah-row:not([hidden])")).toHaveCount(0);
    await expect(page.locator(".ah-manual")).toBeVisible();
    await expect(page.locator(".ah-manual-target")).toHaveText("root@pve02");
    await input.press("Enter");
    await expect(page.locator(".ah-page[data-page='credentials']:not([data-leaving])")).toBeVisible();
  } finally {
    await context.close();
  }
});

test("mouse and shortcut focus draw no rings; Tab navigation does", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='edge-arm']").click();
    const afterClick = await page.evaluate(() => ({
      ring: document.documentElement.dataset.focusRing,
      tick: getComputedStyle(document.querySelector(".ah-row[data-host='edge-arm'] .tick")!).outlineStyle,
      rowBorder: getComputedStyle(document.querySelector(".ah-row[data-host='edge-arm']")!).borderTopStyle,
    }));
    expect(afterClick).toEqual({ ring: "off", tick: "none", rowBorder: "none" });
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBe("on");
    await page.keyboard.press("Meta+k");
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBe("off");
  } finally {
    await context.close();
  }
});

test("the desktop sidebar makes room instead of covering the window", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator("[aria-label='Show hosts']").first().click();
    await page.waitForTimeout(350);
    const reachable = await page.evaluate(() => {
      const close = document.querySelector(".ah-close")!.getBoundingClientRect();
      return !!document.elementFromPoint(close.x + close.width / 2, close.y + close.height / 2)?.closest(".ah-close");
    });
    expect(reachable).toBe(true);
  } finally {
    await context.close();
  }
});

test("steps slide in the direction of travel and Back reverses it", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    await page.waitForTimeout(30);
    const forward = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not([data-leaving])")!).transform).m41);
    expect(forward).toBeGreaterThan(0);
    await page.locator("[data-ah='as-user']").click();
    await expect(page.locator(".ah-page[data-page='success']")).toBeVisible({ timeout: 10_000 });
    await page.locator("[data-ah='again']").click();
    await page.waitForTimeout(30);
    const back = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not([data-leaving])")!).transform).m41);
    expect(back).toBeLessThan(0);
  } finally {
    await context.close();
  }
});

test("root needs explicit consent and a finished host opens its window beside the flow", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    const root = page.locator("[data-ah='as-root']");
    await expect(root).toBeDisabled();
    await page.locator(".ah-consent").click();
    await expect(root).toBeEnabled();
    await root.click();
    await expect(page.locator(".ah-page[data-page='success']")).toBeVisible({ timeout: 10_000 });
    const result = await page.locator(".ah-result").boundingBox();
    expect(result && result.x + result.width <= 1440).toBe(true);
    await expect(page.locator(".ui-toast")).toBeVisible();
  } finally {
    await context.close();
  }
});

test("failures say what happened, what to do, and offer Retry with details", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='pve01']").click();
    await page.locator("[data-ah='continue']").click();
    await expect(page.locator(".ah-page:not([data-leaving]) .ah-title")).toHaveText("Blocked by the mesh policy");
    await expect(page.locator("[data-ah='retry']")).toBeVisible();
    await page.locator(".ah-details summary").click();
    await expect(page.locator(".ah-details pre")).toBeVisible();
  } finally {
    await context.close();
  }
});

for (const width of [320, 375, 393]) {
  test(`phone rows never overlap at ${width} px`, async ({ browser }) => {
    const viewport: Viewport = { width, height: 800, touch: true };
    const { context, page } = await open(browser, viewport, "paper");
    try {
      const overlaps = await page.evaluate(() => {
        const hits: string[] = [];
        for (const row of document.querySelectorAll<HTMLElement>(".ah-row")) {
          const parts = [".ah-name", ".ah-meta", ".ah-status", ".ah-ip"].map((selector) => row.querySelector<HTMLElement>(selector)!.getBoundingClientRect());
          for (let i = 0; i < parts.length; i++) for (let j = i + 1; j < parts.length; j++) {
            const a = parts[i]!, b = parts[j]!;
            if (a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5) hits.push(`${row.dataset.host}:${i}-${j}`);
          }
        }
        return hits;
      });
      expect(overlaps).toEqual([]);
      await press(page, viewport, ".ah-row[data-host='edge-arm']");
      await press(page, viewport, "[data-ah='continue']");
      const buttons = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ah-foot button")].map((button) => Math.round(button.getBoundingClientRect().height)));
      expect(buttons.every((height) => height >= 44)).toBe(true);
    } finally {
      await context.close();
    }
  });
}
