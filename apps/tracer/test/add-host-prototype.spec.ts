/**
 * Exercises the mock-only add-host flow on the canvas (`proto=addhost` is the alias that opens it):
 * one field, quiet selection, consent, outcomes, motion, and the window-card integration.
 */
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
    expect(afterClick).toEqual({ ring: undefined, tick: "none", rowBorder: "none" });
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBe("on");
    await page.keyboard.press("Meta+k");
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBeUndefined();
  } finally {
    await context.close();
  }
});

test("the docked sidebar never covers the flow window and stays out of its way", async ({ browser }) => {
  for (const width of [1440, 1920]) {
    const { context, page } = await open(browser, { width, height: 900 });
    try {
      await page.locator("[aria-label='Show hosts']").first().click();
      await page.waitForTimeout(450);
      const geometry = await page.evaluate(() => ({
        sidebarRight: document.querySelector("#sidebar")!.getBoundingClientRect().right,
        windowLeft: document.querySelector(".ui-window[data-active]")!.getBoundingClientRect().left,
        closeReachable: (() => {
          const rect = document.querySelector("[data-ah='close']")!.getBoundingClientRect();
          return !!document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2)?.closest("[data-ah='close']");
        })(),
      }));
      expect(geometry.windowLeft).toBeGreaterThanOrEqual(geometry.sidebarRight);
      expect(geometry.closeReachable).toBe(true);
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
      pillShadow: getComputedStyle(document.querySelector(".ui-window[data-active] .ui-window-pill")!).boxShadow,
    }));
    expect(card.shadow).not.toBe("none");
    // Superseded: the flow card is the shared translucent overlay material, softly blurred (TASTE §4).
    expect(card.backdrop).toContain("blur(14px)");
    expect(card.scrimAlpha).toContain("0.5");
    expect(card.pillShadow).not.toContain("inset");
    // While the flow owns the window, the capsule is its title once: no separator, session or dot.
    expect((await page.locator("#capsule").innerText()).replace(/\s+/g, " ")).toMatch(/^Add hosts\b(?!.*SSH shell)/);
    await expect(page.locator("#capsule-host")).toHaveText("Add hosts");
    await expect(page.locator("#capsule .capsule-sep")).toBeHidden();
    // No ellipsis in host rows: the secondary line wraps between items instead.
    const clipped = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ah-row[data-host] :is(.ah-name, .ah-meta, .ah-meta > span)")].filter((el) => getComputedStyle(el).textOverflow === "ellipsis").length);
    expect(clipped).toBe(0);
    const windowsBefore = await page.locator(".ui-window").count();
    await page.locator(".ah-row[data-host='edge-arm']").click();
    await page.locator("[data-ah='continue']").click();
    const root = page.locator("[data-ah='as-root']");
    await expect(root).toBeDisabled();
    await page.locator(".ah-consent").click();
    await root.click();
    await expect(page.locator(".ui-window[data-active] .ui-window-title")).toHaveText("ops@edge-arm", { timeout: 10_000 });
    await expect(page.locator(".ah-stage")).toHaveCount(0);
    // The OS name keeps its version: "Debian 12 · aarch64".
    await expect(page.locator(".ui-window[data-active] .canvas-preview")).toContainText("Debian 12 · aarch64");
    // The sidebar tree lists the new host with its session; clicking a row activates and pans to it.
    await page.locator("[aria-label='Show hosts']").first().click();
    // (edge-arm also exists on the canvas, so its section lists both sessions.)
    await expect(page.locator("#tree .bm-sec[data-id='edge-arm'] .bm-leaf", { hasText: "SSH shell" })).toHaveCount(1);
    await expect(page.locator("#tree .bm-leaf[aria-current]")).toHaveCount(1);
    await page.locator("#tree .bm-sec[data-id='build-01'] .bm-leaf").click();
    await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas: { active(): string } }).__tracerCanvas.active())).toBe("build-01:deploy");
    await page.locator("[aria-label='Hide hosts']").first().click();
    // The same window became the terminal: no second window opened for a single host.
    expect(await page.locator(".ui-window").count()).toBe(windowsBefore);
    // One window card component: it carries the shared header, not the wizard's own markup.
    await expect(page.locator(".ui-window[data-active] > .ui-window-head .ui-window-pill")).toHaveCount(1);
    await page.waitForTimeout(500);
    const settled = await page.evaluate(() => {
      const hits: string[] = [];
      // From the terminal text up to the window; the canvas layer above it pans by design.
      for (let el: Element | null = document.querySelector(".ui-window[data-active] .canvas-preview"); el && !el.classList.contains("canvas-layer"); el = el.parentElement) {
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
    const windowsBefore = await page.locator(".ui-window").count();
    await page.locator("[data-ah='continue']").click();
    await page.locator("[data-ah='credentials']").click();
    await page.locator("[data-ah='as-user']").click();
    await expect(page.locator(".ah-job")).toHaveCount(10);
    await expect(page.locator(".ah-job[data-state='failed']")).toHaveCount(2, { timeout: 10_000 });
    await expect(page.locator(".ah-job[data-state='failed'] .ah-job-retry")).toHaveCount(2);
    await expect(page.locator(".ui-toast-message")).toHaveText("8 hosts ready · 2 need attention", { timeout: 20_000 });
    // The flow window plus seven more: each succeeded host has one window, none overlapping.
    await expect(page.locator(".ui-window")).toHaveCount(windowsBefore + 7);
    const overlaps = await page.evaluate(() => {
      const spans = [...document.querySelectorAll(".ui-window")].map((el) => { const r = el.getBoundingClientRect(); return [r.left, r.right] as const; });
      return spans.filter((span, index) => index > 0 && span[0] < spans[index - 1]![1] - 0.5).length;
    });
    expect(overlaps).toBe(0);
    // The canvas's own pan brought the first new window into view.
    await expect.poll(() => page.evaluate(() => { const r = document.querySelector(".ui-window[data-active]")!.getBoundingClientRect(); return `${r.left >= 0 && r.right <= innerWidth} ${Math.round(r.left)}..${Math.round(r.right)} of ${innerWidth}`; })).toMatch(/^true/);
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
