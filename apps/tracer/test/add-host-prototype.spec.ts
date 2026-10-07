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

test("one chip field: typed hosts become chips, checkboxes and chips stay in sync", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await expect(page.locator("[role='tab']")).toHaveCount(0);
    await expect(page.getByText("Discovery sources")).toHaveCount(0);
    const input = page.locator(".ui-chip-text");
    await input.click();
    // The owner's own input: no Enter needed; commas and spaces end tokens.
    await page.keyboard.type("kayg@o2, kayg@o1, kayg@remoternal ", { delay: 10 });
    await expect(page.locator(".ui-chip")).toHaveCount(3);
    await expect(page.locator(".ah-count")).toHaveText("3 selected");
    for (const id of ["o1", "o2", "remoternal"]) await expect(page.locator(`.ah-row[data-host='${id}'] input`)).toBeChecked();
    // Ticking a row adds a chip; removing a chip unticks the row.
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await expect(page.locator(".ui-chip")).toHaveCount(4);
    await page.locator(".ui-chip[data-chip='o1'] .ui-chip-remove").click();
    await expect(page.locator(".ah-row[data-host='o1'] input")).not.toBeChecked();
    // Backspace in an empty field arms, then removes, the last chip.
    await input.focus();
    await input.press("Backspace");
    await expect(page.locator(".ui-chip[data-armed]")).toHaveCount(1);
    await input.press("Backspace");
    await expect(page.locator(".ui-chip")).toHaveCount(2);
    // An unknown user@host becomes a typed-host chip on a delimiter.
    await page.keyboard.type("root@pve02 ", { delay: 10 });
    await expect(page.locator(".ui-chip[data-chip='pve02']")).toHaveCount(1);
    await expect(page.locator(".ah-row[data-host='pve02'] input")).toBeChecked();
  } finally {
    await context.close();
  }
});

test("the field autofocuses on desktop but not on touch", async ({ browser }) => {
  for (const viewport of [DESKTOP, PHONE]) {
    const { context, page } = await open(browser, viewport);
    try {
      const focused = await page.evaluate(() => document.activeElement?.classList.contains("ui-chip-text") ?? false);
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
    const forward = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not(.is-leaving)")!).transform).m41);
    expect(forward).toBeGreaterThan(0);
    await page.waitForTimeout(400);
    await page.locator("[data-ah='back']").click();
    await page.waitForTimeout(30);
    const back = await page.evaluate(() => new DOMMatrix(getComputedStyle(document.querySelector(".ah-page:not(.is-leaving)")!).transform).m41);
    expect(back).toBeLessThan(0);
  } finally {
    await context.close();
  }
});

test("the wizard floats over a dimmed window that becomes the host's terminal", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    const card = await page.evaluate(() => ({
      shadow: getComputedStyle(document.querySelector(".ah-float")!).boxShadow,
      backdrop: getComputedStyle(document.querySelector(".ah-float")!).backdropFilter,
      scrimAlpha: getComputedStyle(document.querySelector(".ah-scrim")!).backgroundColor,
      pillShadow: getComputedStyle(document.querySelector(".ah-pill")!).boxShadow,
    }));
    expect(card.shadow).not.toBe("none");
    expect(card.backdrop).toBe("none");
    expect(card.scrimAlpha).toContain("0.5");
    expect(card.pillShadow).not.toContain("inset");
    const windowsBefore = await page.locator(".window-group").count();
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    const root = page.locator("[data-ah='as-root']");
    await expect(root).toBeDisabled();
    await page.locator(".ah-consent").click();
    await root.click();
    await expect(page.locator(".window-card[data-host-id='edge-arm'] .window-pill-host")).toHaveText("ops@edge-arm", { timeout: 10_000 });
    await expect(page.locator(".ah-stage")).toHaveCount(0);
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
  } finally {
    await context.close();
  }
});

test("ten hosts install together; failures stay listed and the rest open as windows", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    for (const id of ["edge-arm", "nix-cache", "rhel-build", "o1", "o2", "remoternal", "db-01", "web-01", "mon-02", "archive-01"]) {
      await page.locator(`.ah-row[data-host='${id}']`).click();
    }
    await expect(page.locator(".ah-count")).toHaveText("10 selected");
    await page.locator("[data-ah='continue']").click();
    await page.locator("[data-ah='credentials']").click();
    await page.locator("[data-ah='as-user']").click();
    await expect(page.locator(".ah-job")).toHaveCount(10);
    await expect(page.locator(".ah-job[data-state='failed']")).toHaveCount(2, { timeout: 10_000 });
    await expect(page.locator(".ah-job[data-state='failed'] .ah-job-retry")).toHaveCount(2);
    await expect(page.locator(".ui-toast-message")).toHaveText("8 hosts ready · 2 need attention", { timeout: 20_000 });
    await expect(page.locator(".window-card[data-host-id]")).toHaveCount(8);
    await page.locator(".ui-toast-action").click();
    await expect(page.locator(".ah .ah-job[data-state='failed']")).toHaveCount(2);
  } finally {
    await context.close();
  }
});

test("the shared confirmation is compact, icon-only and quiet on open", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    await page.locator("[data-ah='as-user']").click();
    const pill = page.locator(".ah-root-pill");
    await expect(pill).toBeVisible({ timeout: 10_000 });
    await pill.click();
    await expect(page.locator(".ui-confirm-tip")).toHaveAttribute("data-open", "true");
    await page.waitForTimeout(300); // let the scale-in from the trigger settle before measuring
    const metrics = await page.evaluate(() => {
      const buttons = [...document.querySelectorAll<HTMLElement>(".ui-confirm-tip button")];
      return {
        sizes: buttons.map((button) => Math.round(button.getBoundingClientRect().height)),
        labels: buttons.map((button) => button.getAttribute("aria-label")),
        text: buttons.map((button) => button.textContent?.trim()),
        outline: buttons.map((button) => getComputedStyle(button).outlineStyle),
        title: getComputedStyle(document.querySelector(".ui-confirm-tip-message")!).fontSize,
      };
    });
    expect(metrics.sizes).toEqual([28, 28]);
    expect(metrics.labels).toEqual(["Cancel", "Install as root"]);
    expect(metrics.text).toEqual(["", ""]);
    expect(metrics.outline).toEqual(["none", "none"]);
    expect(metrics.title).toBe("13px");
  } finally {
    await context.close();
  }
});

test("failures say what happened, what to do, and offer Retry with details", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='pve01']").click();
    await page.locator("[data-ah='continue']").click();
    await expect(page.locator(".ah-page:not(.is-leaving) .ah-title")).toHaveText("Blocked by the mesh policy");
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
          const parts = [".ah-name", ".ah-meta", ".ah-status"].flatMap((selector) => {
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
