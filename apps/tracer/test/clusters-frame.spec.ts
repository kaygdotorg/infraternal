/**
 * The window frame (#126): the lock glyph on the frame line is never clipped, and a resize moves only the grabbed edge.
 */
import { expect, test, type Page } from "playwright/test";
import { uiFactor } from "./ui-factor";

const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
}

/** Every lock glyph's box lies inside every clipping ancestor, so nothing of it is cut. */
const clippedLocks = (page: Page, view: string): Promise<string[]> => page.evaluate((id) => {
  const bad: string[] = [];
  for (const win of document.querySelectorAll<HTMLElement>(`.cl[data-view="${id}"] .ui-window`)) {
    const svg = win.querySelector(".ui-window-lock svg");
    if (!svg || getComputedStyle(win.querySelector(".ui-window-lock")!).display === "none") continue;
    const g = svg.getBoundingClientRect();
    if (g.right < 0 || g.left > innerWidth) continue; // off screen: nothing to see
    for (let n: Element | null = svg.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      const r = n.getBoundingClientRect();
      let top = r.top, bottom = r.bottom, left = r.left, right = r.right;
      const inset = /inset\(([^)]*)\)/.exec(cs.clipPath);
      const clips = cs.overflowX !== "visible" || cs.overflowY !== "visible" || inset;
      if (!clips) continue;
      if (inset) { const v = inset[1]!.split(" ").map((x) => parseFloat(x)); top += -(v[0] ?? 0) * -1; bottom -= v[2] ?? v[0] ?? 0; left += v[3] ?? v[1] ?? v[0] ?? 0; right -= v[1] ?? v[0] ?? 0; }
      if (cs.overflowX === "visible" && cs.overflowY === "visible" && inset) { /* clip-path only */ }
      const outside = (cs.overflowY !== "visible" || inset) && (g.top < top - 0.5 || g.bottom > bottom + 0.5);
      const outsideX = cs.overflowX !== "visible" && (g.left < left - 0.5 || g.right > right + 0.5);
      if (outside || outsideX) bad.push(`${win.dataset.windowId} clipped by ${(n as HTMLElement).className}`);
    }
  }
  return bad;
}, view);

test("the lock glyph is whole on every window, lone or not, at the top of the view", async ({ page }) => {
  await boot(page);
  for (const view of ["console", "containers", "settings"]) {
    await api(page, "flyView", view);
    await page.waitForTimeout(1300);
    expect(await clippedLocks(page, view), `${view}: clipped locks`).toEqual([]);
  }
});

type Box = { l: number; t: number; r: number; b: number };
const boxesOf = (page: Page, view: string): Promise<Record<string, Box>> => page.evaluate((id) => {
  const out: Record<string, Box> = {};
  for (const w of document.querySelectorAll<HTMLElement>(`.cl[data-view="${id}"] .ui-window`)) { const r = w.getBoundingClientRect(); out[w.dataset.windowId!] = { l: r.left, t: r.top, r: r.right, b: r.bottom }; }
  return out;
}, view);

const CURSORS: Record<string, string> = { n: "ns-resize", s: "ns-resize", e: "ew-resize", w: "ew-resize", ne: "nesw-resize", sw: "nesw-resize", nw: "nwse-resize", se: "nwse-resize" };
const DIRS: Record<string, [number, number]> = { n: [0, -1], s: [0, 1], e: [1, 0], w: [-1, 0], ne: [1, -1], nw: [-1, -1], se: [1, 1], sw: [-1, 1] };

async function drag(page: Page, id: string, edge: string, dx: number, dy: number): Promise<{ during: Box; after: Box }> {
  const handle = page.locator(`.ui-window[data-window-id="${id}"] .ui-window-resize[data-edge="${edge}"]`);
  const hb = (await handle.boundingBox())!;
  const x0 = hb.x + hb.width / 2, y0 = hb.y + hb.height / 2;
  await page.mouse.move(x0, y0);
  await page.mouse.down();
  await page.mouse.move(x0 + dx / 2, y0 + dy / 2, { steps: 3 });
  await page.mouse.move(x0 + dx, y0 + dy, { steps: 3 });
  await page.waitForTimeout(120);
  const during = (await boxesOf(page, await page.evaluate((w) => document.querySelector<HTMLElement>(`.ui-window[data-window-id="${w}"]`)!.closest<HTMLElement>(".cl")!.dataset.view!, id)))[id]!;
  await page.mouse.up();
  await page.waitForTimeout(900);
  const view = await page.evaluate((w) => document.querySelector<HTMLElement>(`.ui-window[data-window-id="${w}"]`)!.closest<HTMLElement>(".cl")!.dataset.view!, id);
  return { during, after: (await boxesOf(page, view))[id]! };
}

/** All eight handles in both directions: the opposite edges hold (0.5 px), neighbours keep their size, cursors match. */
async function audit(page: Page, view: string, id: string, label: string): Promise<void> {
  const widths = (b: Box): [number, number] => [b.r - b.l, b.b - b.t];
  for (const edge of Object.keys(CURSORS)) {
    const handle = page.locator(`.ui-window[data-window-id="${id}"] .ui-window-resize[data-edge="${edge}"]`);
    expect(await handle.evaluate((h) => getComputedStyle(h).cursor), `${label} ${edge} cursor`).toBe(CURSORS[edge]);
    // In first (the window can always shrink), then back out to where it was and a little more.
    for (const sign of [-1, 1]) {
      const before = await boxesOf(page, view);
      const me = before[id]!;
      const [ux, uy] = DIRS[edge]!;
      const { during, after } = await drag(page, id, edge, ux * 50 * sign, uy * 50 * sign);
      const names = `${label} ${edge} ${sign > 0 ? "out" : "in"}`;
      for (const [when, box] of [["during", during], ["after", after]] as const) {
        if (edge.includes("w")) expect(Math.abs(box.r - me.r), `${names} ${when}: right edge`).toBeLessThanOrEqual(0.5);
        if (edge.includes("e")) expect(Math.abs(box.l - me.l), `${names} ${when}: left edge`).toBeLessThanOrEqual(0.5);
        if (edge.includes("n")) expect(Math.abs(box.b - me.b), `${names} ${when}: bottom edge`).toBeLessThanOrEqual(0.5);
        if (edge.includes("s")) expect(Math.abs(box.t - me.t), `${names} ${when}: top edge`).toBeLessThanOrEqual(0.5);
        if (!edge.includes("w") && !edge.includes("e")) { expect(Math.abs(box.l - me.l), `${names} ${when}: left`).toBeLessThanOrEqual(0.5); expect(Math.abs(box.r - me.r), `${names} ${when}: right`).toBeLessThanOrEqual(0.5); }
        if (!edge.includes("n") && !edge.includes("s")) { expect(Math.abs(box.t - me.t), `${names} ${when}: top`).toBeLessThanOrEqual(0.5); expect(Math.abs(box.b - me.b), `${names} ${when}: bottom`).toBeLessThanOrEqual(0.5); }
      }
      // Neighbours are never resized: only their positions may change.
      const now = await boxesOf(page, view);
      for (const other of Object.keys(before)) {
        if (other === id) continue;
        expect(widths(now[other]!).map(Math.round), `${names}: ${other} keeps its size`).toEqual(widths(before[other]!).map(Math.round));
      }
      // Dragging a vertical edge or corner outward changes the width at least; height only has room when it was shortened.
      if (sign > 0 && ux) expect(Math.abs(widths(after)[0] - widths(me)[0]), `${names}: the width followed the pointer`).toBeGreaterThan(5);
    }
  }
}

async function clamps(page: Page, id: string, label: string): Promise<void> {
  const width = async (): Promise<number> => { const b = (await boxesOf(page, await page.evaluate((w) => document.querySelector<HTMLElement>(`.ui-window[data-window-id="${w}"]`)!.closest<HTMLElement>(".cl")!.dataset.view!, id)))[id]!; return b.r - b.l; };
  await drag(page, id, "e", 3000, 0);
  expect(Math.abs((await width()) - Math.round((await page.evaluate(() => document.querySelector<HTMLElement>(".cl-viewport")!.clientWidth)) * 0.99)), `${label}: the widest Window Sizes option`).toBeLessThanOrEqual(1);
  await drag(page, id, "w", 3000, 0);
  // 300 px at the standard factor; the minimum grows with the UI size like the windows do (#283).
  expect(Math.abs((await width()) - Math.round(300 * (await uiFactor(page)))), `${label}: the minimum`).toBeLessThanOrEqual(1);
}

test("every window resizes from its own edges and corners (D195)", async ({ page }) => {
  test.setTimeout(240_000);
  await boot(page);
  await api(page, "setCanvasLock", false);
  // A window in a strip of three columns.
  await api(page, "flyView", "console");
  await page.waitForTimeout(1300);
  const three = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .cl-col')].filter((c) => c.querySelectorAll(":scope > .ui-window").length === 1).map((c) => c.querySelector<HTMLElement>(".ui-window")!.dataset.windowId!));
  expect(three.length).toBeGreaterThanOrEqual(2);
  await audit(page, "console", three[0]!, "three-window strip");
  await clamps(page, three[0]!, "three-window strip");
  // A window alone in its strip: close the other one in Containers.
  await api(page, "flyView", "containers");
  await page.waitForTimeout(1300);
  await page.locator('.cl[data-view="containers"] .ui-window [data-action="close"]').last().evaluate((b) => (b as HTMLElement).click());
  await page.waitForTimeout(900);
  const lone = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="containers"] .ui-window')].map((w) => w.dataset.windowId!));
  expect(lone.length).toBe(1);
  await audit(page, "containers", lone[0]!, "lone window");
  await clamps(page, lone[0]!, "lone window");
});
