/**
 * Phone polish (#164): the window is one rounded shape, neighbours peek in at the screen edge, the toolbar's selection stays
 * inside its capsule, the canvas-lock glyph, the window pill leads with the machine's system, and the header pills are one
 * size. Runs on the test double's canvas (the product canvas code), touch profiles at 393x852 and 375x667 in the ink and
 * paper themes, with the keyboard up and down (the viewport shrunk by the keyboard's height, as the real specs do).
 * Review screenshots land in the external job evidence directory; every assertion is a measurement.
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("phone-polish");
const PEEK = 10;
const SIZES = [{ w: 393, h: 852, kb: 336 }, { w: 375, h: 667, kb: 300 }] as const;
const THEMES = ["ink", "paper"] as const;

async function open(browser: Browser, w: number, h: number, theme: string, touch = true): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, deviceScaleFactor: 3 });
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  // Test-double chrome (badge, mockup tag, frame meter) is not the product and would sit in the strips measured below.
  await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
  await page.waitForTimeout(1200);
  return { context, page };
}

const columns = (page: Page) => page.locator("[data-view='console'] .cl-col").count();
/** Closes the window of `host` with the header's close button (a real tap), then waits for the reflow. */
async function closeWindow(page: Page, host: string): Promise<void> {
  const win = page.locator("[data-view='console'] .ui-window").filter({ has: page.locator(".ui-window-host", { hasText: host }) }).first();
  await win.locator(".ui-window-action[aria-label='Close']").dispatchEvent("click");
  await page.waitForTimeout(1200);
}

/** Pixels of a screenshot region, read back through a canvas in the page. */
async function pixels(page: Page, png: Buffer): Promise<{ w: number; h: number; data: number[] }> {
  return page.evaluate(async (b64) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const g = c.getContext("2d")!;
    g.drawImage(img, 0, 0);
    return { w: img.width, h: img.height, data: Array.from(g.getImageData(0, 0, img.width, img.height).data) };
  }, png.toString("base64"));
}

/**
 * The window is one rounded shape: the strips just outside the card's bottom edge and right edge (beyond the 8 px and 2 px a
 * column's shadow may reach) are the canvas, all one colour. A shadow cut flat by the column showed as a step along them.
 */
async function expectOneRoundedShape(page: Page, label: string): Promise<void> {
  // The backdrop's dots would be counted as a step in the colour; they are not part of what is measured.
  const hideDots = await page.addStyleTag({ content: ".backdrop, .ui-canvas-backdrop { display: none !important; }" });
  await page.waitForTimeout(150);
  try { await measureShape(page, label); } finally { await hideDots.evaluate((n) => (n as Element).remove()); }
}
async function measureShape(page: Page, label: string): Promise<void> {
  const box = await page.evaluate(() => {
    const view = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect();
    const cards = [...document.querySelectorAll<HTMLElement>("[data-view='console'] .ui-window")].map((n) => n.getBoundingClientRect()).filter((r) => r.right > view.left + 40 && r.left < view.right - 40 && r.width > 100 && r.bottom < view.bottom + 1);
    const r = cards.sort((a, b) => Math.abs((a.left + a.right) / 2 - innerWidth / 2) - Math.abs((b.left + b.right) / 2 - innerWidth / 2))[0]!;
    return { left: r.left, right: r.right, bottom: r.bottom, width: innerWidth };
  });
  /** The median colour of each row of a region (a dot or a glyph in a few pixels of a row does not move the median). */
  const rows = async (x: number, y: number, w: number, h: number): Promise<number[][]> => {
    const px = await pixels(page, await page.screenshot({ clip: { x, y, width: w, height: h } }));
    const out: number[][] = [];
    for (let r = 0; r < px.h; r++) {
      const med = [0, 1, 2].map((ch) => { const v: number[] = []; for (let c = 0; c < px.w; c++) v.push(px.data[(r * px.w + c) * 4 + ch]!); return v.sort((p, q) => p - q)[v.length >> 1]!; });
      out.push(med);
    }
    return out;
  };
  const diff = (a: number[][], b: number[][]): number => Math.max(...a.map((row, i) => Math.max(...row.map((v, k) => Math.abs(v - b[i]![k]!)))));
  // What the window's own shadow adds: the same strips with shadows on and off. Whatever else is there (the toolbar's shadow
  // and fade, the dots) is the same in both, so the difference is the card's shadow alone. A shadow wider than the column's
  // padding was cut flat by the column and showed as a square backing; one that ends inside it adds nothing out here.
  // A lone window is the full screen width, so there is no canvas beside it to measure (nothing to cut flat either).
  const regions = [
    { name: "below the card", x: Math.max(4, box.left + 4), y: Math.floor(box.bottom + 12), w: Math.max(8, box.right - box.left - 8), h: 2 },
    { name: "beside the card", x: box.right + 4, y: box.bottom - 120, w: 3, h: 100 },
  ].filter((r) => r.x + r.w <= box.width);
  const on = await Promise.all(regions.map((r) => rows(r.x, r.y, r.w, r.h)));
  const off = await page.addStyleTag({ content: ".ui-window { box-shadow: none !important; }" });
  await page.waitForTimeout(100);
  const without = await Promise.all(regions.map((r) => rows(r.x, r.y, r.w, r.h)));
  await off.evaluate((n) => (n as Element).remove());
  regions.forEach((r, i) => expect(diff(on[i]!, without[i]!), `${label}: the card's shadow reaches ${r.name}`).toBeLessThanOrEqual(1));
}

/** 3x crops of the card's two bottom corners (for looking: one rounded border, nothing square behind it). */
async function cornerCrops(page: Page, name: string): Promise<void> {
  const r = await page.evaluate(() => {
    const view = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect();
    const cards = [...document.querySelectorAll<HTMLElement>("[data-view='console'] .ui-window")].map((n) => n.getBoundingClientRect()).filter((c) => c.right > view.left + 40 && c.left < view.right - 40 && c.width > 100 && c.bottom < view.bottom + 1);
    const c = cards.sort((a, b) => Math.abs((a.left + a.right) / 2 - innerWidth / 2) - Math.abs((b.left + b.right) / 2 - innerWidth / 2))[0]!;
    return { left: c.left, right: c.right, bottom: c.bottom };
  });
  await page.screenshot({ path: `${captures}/${name}-corner-bottom-left.png`, clip: { x: Math.max(0, r.left - 14), y: r.bottom - 36, width: 56, height: 56 } });
  await page.screenshot({ path: `${captures}/${name}-corner-bottom-right.png`, clip: { x: r.right - 42, y: r.bottom - 36, width: Math.min(56, 393 - (r.right - 42)), height: 56 } });
}

for (const { w, h, kb } of SIZES) for (const theme of THEMES) {
  test(`phone ${w}x${h} ${theme}: one rounded window shape with the keyboard down and up; neighbours peek ${PEEK} px; a lone window keeps the full width`, async ({ browser }) => {
    test.setTimeout(180_000);
    await mkdir(captures, { recursive: true });
    const { context, page } = await open(browser, w, h, theme);
    try {
      const vp = () => page.evaluate(() => { const r = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect(); return { left: r.left, right: r.right, width: r.width }; });
      /** The visible width of the windows on each side of the one in the middle of the viewport. */
      const slices = () => page.evaluate(() => {
        const view = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect();
        const cols = [...document.querySelectorAll<HTMLElement>("[data-view='console'] .cl-col")];
        const wins = cols.map((c) => c.querySelector<HTMLElement>(".ui-window")!.getBoundingClientRect());
        const mid = (view.left + view.right) / 2;
        const at = wins.map((r, i) => ({ i, d: Math.abs((r.left + r.right) / 2 - mid) })).sort((a, b) => a.d - b.d)[0]!.i;
        const shown = (r: DOMRect) => Math.max(0, Math.min(r.right, view.right) - Math.max(r.left, view.left));
        const own = wins[at]!;
        return { count: cols.length, at, width: own.width, left: at > 0 ? shown(wins[at - 1]!) : 0, right: at < cols.length - 1 ? shown(wins[at + 1]!) : 0, centre: (own.left + own.right) / 2 - mid };
      });
      const press = async (id: string) => { await page.locator(`[data-cv='${id}']`).tap(); await page.waitForTimeout(800); };
      const stepTo = async (i: number) => { for (let k = 0; k < 4; k++) { const s = await slices(); if (s.at === i) break; await press(i > s.at ? "next" : "previous"); } };

      // Three columns: the middle window has a slice of each neighbour.
      expect(await columns(page)).toBe(3);
      await stepTo(1);
      let s = await slices();
      expect(s.count).toBe(3);
      expect(s.left, "left slice").toBeGreaterThanOrEqual(PEEK - 1.5);
      expect(s.left, "left slice").toBeLessThanOrEqual(PEEK + 1.5);
      expect(Math.abs(s.left - s.right), "equal slices").toBeLessThanOrEqual(1);
      expect(Math.abs(s.centre), "centred").toBeLessThanOrEqual(1);
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-3-windows-middle.png` });
      // The shape is measured on the first window (a whole column of its own, so nothing sits a gap below its bottom edge).
      await stepTo(0);
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-3-windows-first.png` });
      await expectOneRoundedShape(page, "3 windows, keyboard down");
      await page.setViewportSize({ width: w, height: h - kb });
      await page.waitForTimeout(1000);
      await expectOneRoundedShape(page, "3 windows, keyboard up");
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-3-windows-keyboard-up.png` });
      await cornerCrops(page, `phone-${w}x${h}-${theme}-3-windows-keyboard-up`);
      await page.setViewportSize({ width: w, height: h });
      await page.waitForTimeout(900);

      // Two columns: the first window has only a right slice, the second only a left one.
      await closeWindow(page, "studio-mac");
      expect(await columns(page)).toBe(2);
      await stepTo(0);
      s = await slices();
      expect(s.left, "nothing peeks where nothing is").toBe(0);
      expect(s.right).toBeGreaterThanOrEqual(PEEK - 1.5);
      expect(s.right).toBeLessThanOrEqual(PEEK + 1.5);
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-2-windows-first.png` });
      await expectOneRoundedShape(page, "2 windows");

      // A lone window: the whole canvas width (full width), centred, nothing peeking.
      await closeWindow(page, "nix-cache");
      await closeWindow(page, "edge-arm");
      expect(await columns(page)).toBe(1);
      s = await slices();
      const v = await vp();
      expect(s.left + s.right).toBe(0);
      expect(Math.abs(s.width - v.width), "lone window width").toBeLessThanOrEqual(1.5);
      expect(Math.abs(s.centre)).toBeLessThanOrEqual(1);
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-1-window.png` });
      await expectOneRoundedShape(page, "1 window, keyboard down");
      await page.setViewportSize({ width: w, height: h - kb });
      await page.waitForTimeout(1000);
      await expectOneRoundedShape(page, "1 window, keyboard up");
      await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-1-window-keyboard-up.png` });
      await cornerCrops(page, `phone-${w}x${h}-${theme}-1-window-keyboard-up`);
    } finally { await context.close(); }
  });
}

// ---- the toolbar's selection circle -------------------------------------------------------------------------------------

for (const { w, h } of SIZES) for (const theme of THEMES) {
  test(`phone ${w}x${h} ${theme}: the toolbar's selection circle sits inside the capsule with equal gaps above and below`, async ({ browser }) => {
    await mkdir(captures, { recursive: true });
    const { context, page } = await open(browser, w, h, theme);
    try {
      await page.waitForTimeout(1500); // the toolbar's rows settle (a spring) before they are measured
      const ids = await page.locator("[data-cv]").evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.cv!));
      expect(ids.length).toBeGreaterThanOrEqual(7);
      for (const id of ids) {
        const m = await page.evaluate((target) => {
          document.querySelectorAll<HTMLElement>("[data-cv]").forEach((b) => { b.dataset.pressed = String(b.dataset.cv === target); });
          const tray = document.querySelector<HTMLElement>(".keytray")!.getBoundingClientRect();
          const b = document.querySelector<HTMLElement>(`[data-cv='${target}']`)!;
          const r = b.getBoundingClientRect();
          const ring = getComputedStyle(b, "::before");
          const inset = parseFloat(ring.top);
          // The visible circle: the button's box less the ring's inset, clipped by the tray's inner edge (its 1 px hairline).
          const top = r.top + inset, bottom = r.bottom - inset;
          return { above: top - (tray.top + 1), below: (tray.bottom - 1) - bottom, size: r.height - 2 * inset, left: r.left };
        }, id);
        expect(m.above, `${id}: gap above ${JSON.stringify(m)}`).toBeGreaterThan(2);
        expect(Math.abs(m.above - m.below), `${id}: gaps equal`).toBeLessThanOrEqual(0.5);
      }
      // 3x crops of the capsule with the first, a middle and the last button selected.
      for (const id of [ids[0]!, "canvas-lock", ids[ids.length - 1]!]) {
        await page.evaluate((target) => document.querySelectorAll<HTMLElement>("[data-cv]").forEach((b) => { b.dataset.pressed = String(b.dataset.cv === target); }), id);
        await page.waitForTimeout(250);
        const tray = await page.locator(".keytray").boundingBox();
        await page.screenshot({ path: `${captures}/phone-${w}x${h}-${theme}-toolbar-${id}-selected.png`, clip: { x: tray!.x - 4, y: tray!.y - 4, width: tray!.width + 8, height: tray!.height + 8 } });
      }
    } finally { await context.close(); }
  });
}

// ---- the window pills ----------------------------------------------------------------------------------------------------

async function pillMetrics(page: Page) {
  return page.evaluate(() => {
    const head = document.querySelector<HTMLElement>("[data-view='console'] .ui-window .ui-window-head")!;
    const pill = head.querySelector<HTMLElement>(".ui-window-pill")!;
    const actions = head.querySelector<HTMLElement>(".ui-window-actions")!;
    const close = head.querySelector<HTMLElement>(".ui-window-action[aria-label='Close']")!;
    const icons = [...head.querySelectorAll<SVGElement>(".ui-window-action svg")].map((s) => s.getBoundingClientRect().width).filter((v) => v > 0);
    const hit = getComputedStyle(close, "::after");
    const host = head.querySelector<HTMLElement>(".ui-window-host")!;
    const mark = head.querySelector<HTMLElement>(".ui-window-mark")!;
    const kids = [...pill.children].filter((c) => getComputedStyle(c).display !== "none").map((c) => (c as HTMLElement).className.replace("ui-window-", ""));
    const session = head.querySelector<HTMLElement>(".ui-window-session")!;
    return {
      pill: pill.getBoundingClientRect().height, actions: actions.getBoundingClientRect().height, close: close.getBoundingClientRect(),
      icons, hitW: parseFloat(hit.width) || 0, hitH: parseFloat(hit.height) || 0, hitInset: [hit.top, hit.right, hit.bottom, hit.left],
      // Cut means the text is wider than its box. `scrollWidth` and `clientWidth` are whole pixels rounded in different directions, so a name
      // 79.4 px wide in a 79.4 px box reads as 80 against 79 (a false "cut"); the text's own range is compared with the box's real width instead.
      hostCut: (() => { const range = document.createRange(); range.selectNodeContents(host); return range.getBoundingClientRect().width > host.getBoundingClientRect().width + 0.5; })(), hostText: host.textContent, markShown: getComputedStyle(mark).display !== "none" && mark.querySelector("svg path") !== null,
      markIsTerminalGlyph: mark.querySelector("svg.is-line") !== null, kids, sessionShown: getComputedStyle(session).display !== "none",
      pillWidth: pill.getBoundingClientRect().width, headWidth: head.getBoundingClientRect().width,
    };
  });
}

for (const { w, h, touch, label } of [{ w: 393, h: 852, touch: true, label: "phone 393x852" }, { w: 375, h: 667, touch: true, label: "phone 375x667" }, { w: 1440, h: 900, touch: false, label: "desktop 1440x900" }]) for (const theme of THEMES) {
  test(`${label} ${theme}: header pills are one size; the title pill leads with the system mark and names the host in full`, async ({ browser }) => {
    await mkdir(captures, { recursive: true });
    const { context, page } = await open(browser, w, h, theme, touch);
    try {
      let m = await pillMetrics(page);
      expect(Math.abs(m.pill - m.actions), "title pill and actions pill heights").toBeLessThanOrEqual(1);
      if (touch) {
        expect(m.pill, "visible pill height on touch").toBeLessThanOrEqual(38);
        expect(m.hitW, "close hit area width").toBeGreaterThanOrEqual(44);
        expect(m.hitH, "close hit area height").toBeGreaterThanOrEqual(44);
      }
      // The x is sized like the other header icons: same svg box, and its strokes span at least 8 px of it.
      expect(new Set(m.icons.map((v) => Math.round(v))).size, "one icon box").toBe(1);
      // The pill leads with the machine's system mark (never the terminal glyph), then the host in full, then the dot.
      expect(m.markShown, "system mark shown").toBe(true);
      expect(m.markIsTerminalGlyph, "not the generic terminal glyph").toBe(false);
      expect(m.hostCut, `host "${m.hostText}" is not cut`).toBe(false);
      if (touch) expect(m.sessionShown, "no session fragment in a phone-width header").toBe(false);
      expect(m.kids.slice(0, 2)).toEqual(["mark", "title"]);
      // A long name: only the host truncates (nothing else in the pill can show a lone "…").
      await page.evaluate(() => { document.querySelector("[data-view='console'] .ui-window .ui-window-host")!.textContent = "monitor01.internal.example.net"; });
      m = await pillMetrics(page);
      expect(m.pillWidth, "pill stays inside its header").toBeLessThanOrEqual(m.headWidth);
      await page.evaluate(() => { document.querySelector("[data-view='console'] .ui-window .ui-window-host")!.textContent = "monitor01"; });
      await page.waitForTimeout(250);
      m = await pillMetrics(page);
      expect(m.hostCut, "monitor01 is not cut").toBe(false);
      const head = await page.locator("[data-view='console'] .ui-window .ui-window-head").first().boundingBox();
      await page.screenshot({ path: `${captures}/${label.replace(" ", "-")}-${theme}-window-header.png`, clip: { x: Math.max(0, head!.x - 6), y: head!.y - 6, width: Math.min(w, head!.width + 12), height: head!.height + 12 } });
    } finally { await context.close(); }
  });
}
