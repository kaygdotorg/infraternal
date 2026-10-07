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
    await expect(page.locator(".ah-candidate")).toBeHidden();
    await input.fill("");
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator(".ah-row[data-host='nix-cache']").click();
    await input.fill("root@pve02");
    // Selected hosts stay listed under the candidate; nothing selected is hidden.
    await expect(page.locator(".ah-row[data-host]:not([hidden])")).toHaveCount(2);
    await expect(page.locator(".ah-candidate")).toBeVisible();
    await expect(page.locator(".ah-manual-target")).toHaveText("root@pve02");
    await input.press("Enter");
    await expect(page.locator(".ah-row[data-host='pve02'] input")).toBeChecked();
    await expect(page.locator(".ah-count")).toHaveText("3 selected");
    await expect(input).toHaveValue("");
    await page.locator("[data-ah='continue']").click();
    await expect(page.locator(".ah-page[data-page='credentials']:not([data-leaving])")).toBeVisible();
  } finally {
    await context.close();
  }
});

test("the field autofocuses on desktop but not on touch", async ({ browser }) => {
  for (const viewport of [DESKTOP, PHONE]) {
    const { context, page } = await open(browser, viewport);
    try {
      const focused = await page.evaluate(() => document.activeElement?.classList.contains("ah-input") ?? false);
      expect(focused).toBe(!viewport.touch);
    } finally {
      await context.close();
    }
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

test("the sidebar moves the window only by what it would cover", async ({ browser }) => {
  for (const [width, expected] of [[1440, 324], [1920, null]] as const) {
    const { context, page } = await open(browser, { width, height: 900 });
    try {
      const left = () => page.evaluate(() => Math.round(document.querySelector(".ah-group")!.getBoundingClientRect().left));
      const before = await left();
      await page.locator("[aria-label='Show hosts']").first().click();
      await page.waitForTimeout(450);
      // Wide screens leave the window where it is; narrower ones shift it just past the sidebar.
      expect(await left()).toBe(expected ?? before);
      const close = await page.evaluate(() => {
        const rect = document.querySelector("[data-ah='close']")!.getBoundingClientRect();
        return !!document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2)?.closest("[data-ah='close']");
      });
      expect(close).toBe(true);
      await page.locator("[aria-label='Hide hosts']").first().click();
      await page.waitForTimeout(450);
      expect(await left()).toBe(before);
    } finally {
      await context.close();
    }
  }
});

test("steps slide in the direction of travel and Back reverses it", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='pve01']").click();
    await page.locator("[data-ah='continue']").click();
    await page.waitForTimeout(30);
    const forward = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not([data-leaving])")!).transform).m41);
    expect(forward).toBeGreaterThan(0);
    await page.waitForTimeout(400);
    await page.locator("[data-ah='back']").click();
    await page.waitForTimeout(30);
    const back = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not([data-leaving])")!).transform).m41);
    expect(back).toBeLessThan(0);
  } finally {
    await context.close();
  }
});

test("the wizard window becomes the host's terminal, with crisp text at rest", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    const windowsBefore = await page.locator(".window-group").count();
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    const root = page.locator("[data-ah='as-root']");
    await expect(root).toBeDisabled();
    await page.locator(".ah-consent").click();
    await expect(root).toBeEnabled();
    await root.click();
    await expect(page.locator(".window-card[data-host-id='edge-arm'] .window-pill-host")).toHaveText("ops@edge-arm", { timeout: 10_000 });
    await expect(page.locator(".window-card[data-host-id='edge-arm'] .window-fake-output")).toBeVisible();
    expect(await page.locator(".window-group").count()).toBe(windowsBefore);
    await page.waitForTimeout(500);
    const settled = await page.evaluate(() => {
      const hits: string[] = [];
      for (let el: Element | null = document.querySelector(".window-card[data-host-id='edge-arm'] .window-fake-output"); el; el = el.parentElement) {
        const style = getComputedStyle(el);
        if (style.transform !== "none" || style.willChange !== "auto") hits.push(el.className.toString());
      }
      return hits;
    });
    expect(settled).toEqual([]);
    await expect(page.locator(".ui-toast-message")).toHaveCSS("font-size", "13px");
    await page.locator(".ui-toast-action").click();
    await expect(page.locator(".ah .ah-page[data-page='discovery']")).toBeVisible();
    await expect(page.locator(".ah .ah-row[data-host='edge-arm']")).toHaveClass(/is-added/);
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
        for (const row of document.querySelectorAll<HTMLElement>(".ah-row[data-host]")) {
          const parts = [".ah-name", ".ah-meta", ".ah-status", ".ah-ip"].flatMap((selector) => {
            const part = row.querySelector<HTMLElement>(selector);
            return part ? [part.getBoundingClientRect()] : [];
          });
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
