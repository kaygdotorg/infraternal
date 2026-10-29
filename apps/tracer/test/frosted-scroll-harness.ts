/**
 * A scripted sideways pan of the canvas, measured with a Chromium trace (#256). Shared by the report spec
 * (`frosted-scroll-report.spec.ts`, the numbers on the issue) and the assertion spec (`frosted-scroll.spec.ts`).
 *
 * What it does: opens the clusters mockup with the owner's look (Tokyo Night, mesh, Frosted cards), puts exactly
 * `count` windows in the Console view, frees the canvas (no snapping) and pans it sideways for `ms` with one wheel
 * event per animation frame on a sine (about 1,250 px/s at its fastest, one full swing in 1.5 s), so the same windows
 * stay on screen for the whole run. The wheel handler is the real one; only the delivery is scripted, so no
 * round trip to the test runner paces the frames.
 *
 * What it reports: the animation-frame gaps (p50, p95, max), the time the trace spends in paint, layerize, raster and
 * in the compositor's draw (`Display::DrawAndSwap`: where a backdrop blur is paid), and the layer count (DevTools
 * LayerTree). Headless timings on a machine without a GPU are relative only: compare two runs on the same machine
 * back to back, never read them as device numbers.
 */
import { expect, type Browser, type BrowserContext, type CDPSession, type Page } from "playwright/test";

type TraceEvent = { name: string; ph: string; dur?: number };

export interface ScrollOptions {
  /** Window level for the windows: 1 Solid (frosting off, the baseline), 4 Frosted. */
  windows: 1 | 4;
  /** How many windows the Console view holds (1, 4 or 12). */
  count: number;
  /** `live` keeps the blur running while the canvas moves (`?glass=live`). */
  glass?: "live";
  /** Card level (the floating chrome). The owner's setting is 4, Frosted. */
  card?: 1 | 2 | 3 | 4;
  /** Device pixel ratio of the page. */
  dpr?: 1 | 2;
  /** How long the pan runs. */
  ms?: number;
  /** Extra CSS for an experiment (never used by the specs that assert). */
  css?: string;
}

export interface Sample {
  /** The world carried `data-moving` when this was taken. */
  moving: boolean;
  /** `backdrop-filter` of every window that was on screen. */
  windows: string[];
  /** `backdrop-filter` of the floating chrome that was on screen (pills, panels). */
  cards: string[];
}

export interface ScrollResult {
  frames: number[];
  p50: number;
  p95: number;
  max: number;
  /** Milliseconds in each part of the trace over the whole run, and per drawn frame for the draw. */
  ms: { paint: number; layerize: number; raster: number; draw: number; drawPerFrame: number };
  layers: { first: number; max: number; last: number };
  onscreen: number;
  /** What the page looked like in the middle of the pan. */
  mid: Sample;
}

export const percentile = (values: number[], q: number): number => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] ?? 0;
};

const base = (): string => `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`;

/** Splits the largest window downwards, or closes the last, until the Console view holds `count` windows. */
async function shapeConsole(page: Page, count: number): Promise<void> {
  const held = (): Promise<number> => page.evaluate(() => document.querySelectorAll('.cl[data-view="console"] .ui-window').length);
  while ((await held()) > count) {
    await page.locator('.cl[data-view="console"] .ui-window [data-action="close"]').last().evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(250);
  }
  while ((await held()) < count) {
    const largest = await page.evaluate(() => {
      let best = 0, area = 0;
      document.querySelectorAll('.cl[data-view="console"] .ui-window').forEach((w, i) => {
        const r = w.getBoundingClientRect();
        if (r.width * r.height > area) { area = r.width * r.height; best = i; }
      });
      return best;
    });
    await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').nth(largest).click({ position: { x: 20, y: 40 } });
    await page.keyboard.press("Control+Shift+E"); // split down: the columns fill the screen with even rows
    await page.waitForTimeout(250);
  }
  await page.waitForTimeout(800);
}

export interface OpenCanvas { context: BrowserContext; page: Page; cdp: CDPSession }

/** Opens the mockup with `count` windows in Console and the canvas free, ready to pan. */
export async function openCanvas(browser: Browser, options: ScrollOptions): Promise<OpenCanvas> {
  const context = await browser.newContext({ baseURL: base(), viewport: { width: 1440, height: 900 }, deviceScaleFactor: options.dpr ?? 1 });
  const page = await context.newPage();
  const query = `mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=${options.card ?? 4}&windows=${options.windows}${options.glass ? `&glass=${options.glass}` : ""}`;
  await page.goto(`/?${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (options.css) await page.addStyleTag({ content: options.css });
  await page.waitForTimeout(1500);
  const api = (fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
  await api("flyView", "console");
  await page.waitForTimeout(1200);
  await shapeConsole(page, options.count);
  await api("setCanvasLock", false);
  await page.waitForTimeout(500);
  return { context, page, cdp: await context.newCDPSession(page) };
}

/** Pans for `ms`, tracing, and samples the page's glass in the middle of the pan. */
export async function pan(open: OpenCanvas, ms = 3000): Promise<ScrollResult> {
  const { page, cdp } = open;
  const events: TraceEvent[] = [];
  const layerCounts: number[] = [];
  (cdp as unknown as { on(n: string, f: (e: { value: TraceEvent[] }) => void): void }).on("Tracing.dataCollected", (e) => { events.push(...e.value); });
  (cdp as unknown as { on(n: string, f: (e: { layers?: unknown[] }) => void): void }).on("LayerTree.layerTreeDidChange", (e) => { if (e.layers) layerCounts.push(e.layers.length); });
  await cdp.send("LayerTree.enable");
  await page.evaluate((total) => {
    const w = window as unknown as { __pan: { frames: number[]; stop: boolean; mid?: Sample } };
    w.__pan = { frames: [], stop: false };
    const viewport = document.querySelector(".cl-viewport")!;
    const blur = (e: Element): string => getComputedStyle(e).backdropFilter;
    const t0 = performance.now();
    let last = t0, sampled = false;
    const tick = (t: number): void => {
      w.__pan.frames.push(t - last); last = t;
      const dx = Math.round(20 * Math.sin((2 * Math.PI * (t - t0)) / 1500));
      viewport.dispatchEvent(new WheelEvent("wheel", { deltaX: dx, deltaY: 0, bubbles: true, cancelable: true, clientX: 720, clientY: 450 }));
      if (!sampled && t - t0 > total / 2) {
        sampled = true;
        const visible = (e: Element): boolean => e.getBoundingClientRect().width > 0 && getComputedStyle(e).visibility !== "hidden";
        w.__pan.mid = {
          moving: document.querySelector(".cl-world")!.hasAttribute("data-moving"),
          windows: [...document.querySelectorAll(".ui-window[data-onscreen]")].map(blur),
          cards: [...document.querySelectorAll(".ui-pill, .ui-overlay-surface, .ui-panel")].filter(visible).map(blur),
        };
      }
      if (!w.__pan.stop) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, ms);
  await cdp.send("Tracing.start", { categories: "devtools.timeline,cc,gpu,viz,disabled-by-default-devtools.timeline", transferMode: "ReportEvents" });
  await page.waitForTimeout(ms);
  const complete = new Promise<void>((resolve) => cdp.once("Tracing.tracingComplete", () => resolve()));
  await cdp.send("Tracing.end");
  await complete;
  const done = await page.evaluate(() => {
    const w = window as unknown as { __pan: { frames: number[]; stop: boolean; mid: Sample } };
    w.__pan.stop = true;
    return { frames: w.__pan.frames.slice(2), mid: w.__pan.mid, onscreen: document.querySelectorAll(".ui-window[data-onscreen]").length };
  });
  await cdp.send("LayerTree.disable");
  const total = (name: string): number => events.filter((e) => e.ph === "X" && e.name === name).reduce((a, e) => a + (e.dur ?? 0), 0) / 1000;
  const drawn = events.filter((e) => e.ph === "X" && e.name === "Display::DrawAndSwap").length;
  return {
    frames: done.frames,
    p50: percentile(done.frames, 0.5),
    p95: percentile(done.frames, 0.95),
    max: Math.max(...done.frames),
    ms: { paint: total("Paint"), layerize: total("Layerize"), raster: total("RasterTask"), draw: total("Display::DrawAndSwap"), drawPerFrame: total("Display::DrawAndSwap") / Math.max(1, drawn) },
    layers: { first: layerCounts[0] ?? 0, max: Math.max(0, ...layerCounts), last: layerCounts.at(-1) ?? 0 },
    onscreen: done.onscreen,
    mid: done.mid,
  };
}

/** One full measurement: open, pan, close. */
export async function measure(browser: Browser, options: ScrollOptions): Promise<ScrollResult> {
  const open = await openCanvas(browser, options);
  try { return await pan(open, options.ms); } finally { await open.context.close(); }
}
