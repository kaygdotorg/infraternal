/**
 * Memory footprint on a phone (issue #89): a locked iPhone restores the page with a tight memory budget, and a
 * WebContent process that goes over it is killed in a loop. This measures what the page holds at 393x852, DPR 3:
 * the composited layer tree (area in device pixels, 4 bytes each), the canvases and their backing stores, and
 * the DOM and heap counters. Numbers are printed as `MEM ...`.
 */
import { expect, test, devices, type Page } from "playwright/test";

type LayerInfo = { layerId: string; width: number; height: number; drawsContent: boolean; backendNodeId?: number; offsetX?: number; offsetY?: number; transform?: number[]; reasons?: string[]; node?: string };

export async function memory(page: Page): Promise<{ nearMB: number; layerMB: number; layers: number; biggest: Array<[number, number, string[], string]>; canvases: Array<[number, number]>; canvasMB: number; counters: Record<string, number>; metrics: Record<string, number> }> {
  const cdp = await page.context().newCDPSession(page);
  const layers: LayerInfo[] = [];
  await cdp.send("DOM.enable");
  await cdp.send("LayerTree.enable");
  const done = new Promise<void>((resolve) => cdp.once("LayerTree.layerTreeDidChange", (e: { layers?: LayerInfo[] }) => { layers.push(...(e.layers ?? [])); resolve(); }));
  await page.evaluate(() => { document.body.style.setProperty("--poke", String(Math.random())); });
  await done;
  for (const l of layers) {
    try { const r = (await cdp.send("LayerTree.compositingReasons", { layerId: l.layerId })) as { compositingReasonIds?: string[] }; if (r.compositingReasonIds) l.reasons = r.compositingReasonIds; } catch { /* the layer may be gone */ }
  }
  for (const l of layers) {
    if (!l.backendNodeId) continue;
    try { const d = (await cdp.send("DOM.describeNode", { backendNodeId: l.backendNodeId })) as { node: { nodeName: string; attributes?: string[] } }; const at = d.node.attributes ?? []; const cls = at[at.indexOf("class") + 1] ?? ""; l.node = `${d.node.nodeName.toLowerCase()}.${cls.split(" ").slice(0, 2).join(".")}`; } catch { /* gone */ }
  }
  const dpr = await page.evaluate(() => devicePixelRatio);
  // The layer tree reports CSS-pixel sizes; backing stores are width*height*dpr^2 device pixels at 4 bytes.
  const area = layers.filter((l) => l.drawsContent).map((l) => l.width * l.height * dpr * dpr);
  const layerMB = area.reduce((a, b) => a + b, 0) * 4 / 1048576;
  // What a tiled compositor rasters is about the layer's part within one screen of the visible area (tiles near it).
  const vw = await page.evaluate(() => innerWidth), vh = await page.evaluate(() => innerHeight);
  const near = layers.filter((l) => l.drawsContent).map((l) => {
    const m = l.transform ?? [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    const x0 = (l.offsetX ?? 0) + (m[12] ?? 0), y0 = (l.offsetY ?? 0) + (m[13] ?? 0), sx = m[0] ?? 1, sy = m[5] ?? 1;
    const w = Math.max(0, Math.min(x0 + l.width * sx, 2 * vw) - Math.max(x0, -vw)), h = Math.max(0, Math.min(y0 + l.height * sy, 2 * vh) - Math.max(y0, -vh));
    return w * h * dpr * dpr;
  });
  const nearMB = near.reduce((a, b) => a + b, 0) * 4 / 1048576;
  const canvases = await page.evaluate(() => [...document.querySelectorAll("canvas")].map((c) => [c.width, c.height] as [number, number]));
  const counters = ((await cdp.send("Memory.getDOMCounters")) as unknown as Record<string, number>);
  const metrics = Object.fromEntries(((await cdp.send("Performance.getMetrics")) as { metrics: Array<{ name: string; value: number }> }).metrics.filter((m) => ["JSHeapUsedSize", "Nodes", "LayoutObjects", "Documents"].includes(m.name)).map((m) => [m.name, m.value]));
  const biggest = layers.filter((l) => l.drawsContent).sort((a, b) => b.width * b.height - a.width * a.height).slice(0, 12).map((l) => [Math.round(l.width), Math.round(l.height), l.reasons ?? [], l.node ?? "?"] as [number, number, string[], string]);
  return { nearMB: +nearMB.toFixed(1), layerMB: +layerMB.toFixed(1), layers: area.length, biggest, canvases, canvasMB: +(canvases.reduce((a, [w, h]) => a + w * h * 4, 0) / 1048576).toFixed(1), counters, metrics };
}

for (const scene of [1, 6]) {
  test(`memory: scene ${scene} on a phone holds little`, async ({ browser }) => {
    test.setTimeout(60_000);
    const context = await browser.newContext({ ...devices["iPhone 15"], deviceScaleFactor: 3 });
    const page = await context.newPage();
    await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&fps=0`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2500);
    const m = await memory(page);
    console.log(`MEM scene ${scene} ` + JSON.stringify(m));
    await context.close();
  });
}

test("memory: a hidden page releases its surfaces and a shown page draws them again", async ({ browser }) => {
  test.setTimeout(60_000);
  const context = await browser.newContext({ ...devices["iPhone 15"], deviceScaleFactor: 3 });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&fps=0");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.keyboard.press("Escape");
  await page.waitForTimeout(1500);
  const canvasPixels = (): Promise<number> => page.evaluate(() => [...document.querySelectorAll("canvas")].reduce((a, c) => a + c.width * c.height, 0));
  const shown = async (): Promise<number> => (await page.evaluate(() => [...document.querySelectorAll(".ui-canvas-backdrop-layer")].filter((l) => !(l as HTMLElement).hidden).length));
  const before = { canvas: await canvasPixels(), layers: await shown() };
  expect(before.canvas).toBeGreaterThan(0);
  expect(before.layers).toBeGreaterThan(0);
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, get: () => true }); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForTimeout(300);
  expect(await canvasPixels()).toBe(0);
  expect(await shown()).toBe(0);
  expect(await page.evaluate(() => document.querySelector<HTMLElement>(".cl-world")!.style.willChange)).toBe("");
  const heldHidden = await memory(page);
  console.log("MEM hidden " + JSON.stringify({ nearMB: heldHidden.nearMB, layerMB: heldHidden.layerMB, layers: heldHidden.layers, canvases: heldHidden.canvases }));
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, get: () => false }); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForTimeout(500);
  expect(await canvasPixels()).toBe(before.canvas);
  expect(await shown()).toBe(before.layers);
  await context.close();
});
