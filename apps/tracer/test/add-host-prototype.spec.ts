/**
 * Exercises the mock-only add-host flow on the canvas (`proto=addhost` is the alias that opens it):
 * one field, quiet selection, consent, outcomes, motion, and the window-card integration.
 */
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";
import { uiFactor } from "./ui-factor";

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
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
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
    // Backspace in an empty field returns the last chip to editable text.
    await input.focus();
    await input.press("Backspace");
    await expect(input).toHaveValue("edge-arm");
    await expect(page.locator(".ui-chip")).toHaveCount(2);
    await input.fill("");
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
    // Observe each real arriving pane before the next animation frame. Sampling
    // 30 ms after a Playwright round trip can instead catch spring overshoot.
    await page.evaluate(() => {
      const arrivals: Array<{ page: string; x: number }> = [];
      (window as unknown as { paneArrivals: Array<{ page: string; x: number }> }).paneArrivals = arrivals;
      new MutationObserver((records) => {
        for (const record of records) for (const node of record.addedNodes) {
          if (node instanceof HTMLElement && node.matches(".ah-page")) {
            arrivals.push({ page: node.dataset.page!, x: new DOMMatrix(getComputedStyle(node).transform).m41 });
          }
        }
      }).observe(document.querySelector(".ah-float .ui-pane-viewport")!, { childList: true });
    });
    await page.locator(".ah-row[data-host='pve01']").click();
    await page.locator("[data-ah='continue']").click();
    const arrivals = () => page.evaluate(() => (window as unknown as { paneArrivals: Array<{ page: string; x: number }> }).paneArrivals);
    await expect.poll(async () => (await arrivals()).length).toBe(1);
    expect((await arrivals())[0]!.x).toBeGreaterThan(0);
    await page.locator("[data-ah='back']").click();
    await expect.poll(async () => (await arrivals()).find((pane) => pane.page === "discovery")?.x).toBeLessThan(0);
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
    expect(card.backdrop).toContain("blur(8px)");
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
    // The toast's type is drawn in rem: 13 px at the standard size times the UI size's factor (#283, TASTE "The size of the whole UI").
    await expect(page.locator(".ui-toast-message")).toHaveCSS("font-size", `${13 * await uiFactor(page)}px`);
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
    await page.getByRole("button", { name: "Review", exact: true }).click();
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
    // The confirmation is the same translucent overlay material as the other floating cards, and
    // it stays inside the window it belongs to.
    const surface = await page.evaluate(() => {
      const read = (el: Element) => { const s = getComputedStyle(el); return { background: s.backgroundColor, filter: s.backdropFilter }; };
      const tip = document.querySelector(".ui-confirm-tip")!;
      const win = document.querySelector(".ui-window[data-active]")!.getBoundingClientRect();
      const box = tip.getBoundingClientRect();
      const probe = document.createElement("div");
      probe.className = "ui-overlay-surface";
      document.body.append(probe);
      const card = read(probe);
      probe.remove();
      return { tip: read(tip), card, inside: box.left >= win.left + 8 && box.right <= win.right - 8 && box.bottom <= win.bottom - 8 };
    });
    expect(surface.tip).toEqual(surface.card);
    expect(surface.inside).toBe(true);
    // The icon buttons are 28 px at the standard size and drawn in rem, so they grow with the UI size's factor (#283).
    const factor = await uiFactor(page);
    expect(metrics.sizes).toEqual([Math.round(28 * factor), Math.round(28 * factor)]);
    expect(metrics.labels).toEqual(["Cancel", "Install as root"]);
    expect(metrics.text).toEqual(["", ""]);
    expect(metrics.outline).toEqual(["none", "none"]);
    expect(metrics.title).toBe(`${13 * factor}px`);
  } finally {
    await context.close();
  }
});

test("failures say what happened, what to do, and offer Retry with details", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.locator(".ah-row[data-host='pve01']").click();
    await page.locator("[data-ah='continue']").click();
    await expect(page.locator(".ah-page:not(.is-leaving) .ah-title")).toHaveText("This server can't connect to pve01");
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
      // Measure visible controls after the shared opening spring settles;
      // progress hides its footer and transformed rectangles are transient.
      await expect.poll(async () => page.evaluate(() => {
        const buttons = [...document.querySelectorAll<HTMLElement>(".ah-foot button")].filter((button) => button.getClientRects().length > 0);
        return buttons.length > 0 ? Math.min(...buttons.map((button) => button.getBoundingClientRect().height)) : 0;
      })).toBeGreaterThanOrEqual(43.5);
      await press(page, viewport, "[data-ah='continue']");
    } finally {
      await context.close();
    }
  });
}

// ---- the flow card is a floating card like the others (TASTE §4) --------------------------
async function runToProgress(page: Page, viewport: Viewport): Promise<void> {
  for (const id of ["o1", "o2", "remoternal"]) await press(page, viewport, `.ah-row[data-host='${id}']`);
  await press(page, viewport, "[data-ah='continue']");
  for (let step = 0; step < 4; step++) {
    if (await page.locator(".ah-page[data-page='progress']").count()) break;
    await page.waitForTimeout(500);
    const next = (await page.locator("[data-ah='credentials']").count()) ? "[data-ah='credentials']" : (await page.locator("[data-ah='as-user']").count()) ? "[data-ah='as-user']" : "[data-ah='continue']";
    await press(page, viewport, next);
  }
  await expect(page.locator(".ah-page[data-page='progress']")).toBeVisible();
  await page.waitForTimeout(900);
}

for (const viewport of [DESKTOP, PHONE]) {
  test(`flow card: shared overlay material, inside its window with one inset, lists end with padding (${viewport.width}×${viewport.height})`, async ({ browser }) => {
    const { context, page } = await open(browser, viewport);
    try {
      const material = await page.evaluate(() => {
        const read = (el: Element) => { const s = getComputedStyle(el); return { background: s.backgroundColor, filter: s.backdropFilter }; };
        const probe = document.createElement("div");
        probe.className = "ui-overlay-surface";
        document.body.append(probe);
        const shared = read(probe);
        probe.remove();
        return { card: read(document.querySelector(".ah-float")!), shared };
      });
      expect(material.card).toEqual(material.shared);
      await page.waitForTimeout(600); // the card's rise settles before it is measured
      const inset = await page.evaluate(() => {
        const f = document.querySelector(".ah-float")!.getBoundingClientRect();
        const w = document.querySelector(".ah.ui-window")!.getBoundingClientRect();
        return { left: f.left - w.left, right: w.right - f.right, bottom: w.bottom - f.bottom };
      });
      // 8 px window padding plus the 1 px frame, never less, and the same on each side.
      for (const side of [inset.left, inset.right, inset.bottom]) expect(side).toBeGreaterThanOrEqual(8.5);
      if (viewport.touch) for (const side of [inset.left, inset.right, inset.bottom]) expect(Math.abs(side - 9)).toBeLessThan(1.5);
      await runToProgress(page, viewport);
      const tail = await page.evaluate(() => {
        const card = document.querySelector(".ah-float")!.getBoundingClientRect();
        const last = [...document.querySelectorAll(".ah-job")].at(-1)!.getBoundingClientRect();
        return card.bottom - last.bottom;
      });
      // The last host row ends at least 28 px above the card's edge.
      expect(tail).toBeGreaterThanOrEqual(28);
    } finally {
      await context.close();
    }
  });
}
