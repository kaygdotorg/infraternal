/**
 * The frame meter and frame-drop recorder (issue #116): an incident reaches the mock server's file with its cause,
 * the meter's frame body costs next to nothing, and it causes no layout or style recalculation between repaints.
 * `?fps=bench` mounts the meter with its measuring hooks (`window.__perfHud`).
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const file = resolve(import.meta.dirname, "..", "test-results", "perf", `${port}.jsonl`);
const URL = "/?mock=1&proto=clusters&scene=7&theme=ink&bg=none";

type Hud = { bench(calls?: number, batch?: number): { meanUs: number; p99Us: number; maxUs: number }; selfTime(): { frames: number; meanMs: number }; pauseRepaint(): void; flush(): void; finish(): void; state(): { sid: string; incidents: number; refresh: number } };
const hud = (page: Page) => ({
  call: <T,>(fn: (h: Hud) => T): Promise<T> => page.evaluate(`(${fn.toString()})(window.__perfHud)`) as Promise<T>,
});

async function open(page: Page, query = "&fps=bench"): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(URL + query);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (query.includes("bench")) await page.waitForFunction("!!window.__perfHud", undefined, { timeout: 10_000 });
  await page.keyboard.press("Control+Shift+G"); // canvas lock off: free pan
  await page.waitForTimeout(1500);
}

test("a 200 ms stall during a pan reaches the file as one freeze, with its activity and script", async ({ page }) => {
  test.setTimeout(60_000);
  await open(page);
  // The stall lives in a script of its own, so a long-animation-frame entry can name it.
  await page.addScriptTag({ content: `
    window.__stall = false;
    function perfSpecStall() { const end = performance.now() + 200; while (performance.now() < end) { /* busy */ } }
    document.querySelector(".cl-viewport").addEventListener("wheel", () => { if (window.__stall) { window.__stall = false; requestAnimationFrame(perfSpecStall); } }, { capture: true });
    //# sourceURL=perf-spec-stall.js` });
  await page.evaluate(() => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (t: number): void => {
      if (t - start > 900) { done(); return; }
      if (t - start > 400 && !(window as unknown as { __armed?: boolean }).__armed) { (window as unknown as { __armed: boolean; __stall: boolean }).__armed = true; (window as unknown as { __stall: boolean }).__stall = true; }
      target.dispatchEvent(new WheelEvent("wheel", { deltaX: 24, deltaY: 9, clientX: 720, clientY: 450, bubbles: true, cancelable: true }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }));
  await page.waitForTimeout(1200);
  const sid = (await hud(page).call((h) => { h.finish(); h.flush(); return h.state().sid; }));
  await expect.poll(async () => (await readFile(file, "utf8").catch(() => "")).includes(sid), { timeout: 8000 }).toBe(true);
  const lines = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Record<string, any>).filter((l) => l.sid === sid);
  const incidents = lines.filter((l) => l.t === "incident" && l.kind === "freeze" && l.activity === "pan");
  console.log("PERF-INCIDENT", JSON.stringify(incidents[0]));
  expect(lines.some((l) => l.t === "session")).toBe(true);
  expect(incidents).toHaveLength(1);
  const [incident] = incidents;
  expect(incident!.activity).toBe("pan");
  expect(incident!.worstMs).toBeGreaterThan(190);
  expect(incident!.page).toContain("proto=clusters");
  expect(incident!.intervals.length).toBeGreaterThan(10);
  expect(incident!.loaf.length).toBeGreaterThan(0);
  const scripts = incident!.loaf.flatMap((f: { scripts: Array<{ src: string; ms: number }> }) => f.scripts);
  expect(scripts.some((s: { src: string; ms: number }) => s.src.includes("perf-spec-stall") && s.ms > 150)).toBe(true);
});

test("the frame body costs under 0.05 ms and the meter causes no layout or style work between repaints", async ({ page }) => {
  test.setTimeout(240_000);
  await open(page);
  const bench = await hud(page).call((h) => h.bench());
  console.log("PERF-BENCH", JSON.stringify(bench));
  expect(bench.meanUs).toBeLessThan(50);
  expect(bench.p99Us).toBeLessThan(50);
  // A page with the mockup's own looping animations gets main-thread frames only when something asks for them; any
  // rAF loop asks every frame, so the loop itself (empty or not) makes the page's animations recalculate style each
  // frame. The control is therefore a page with an EMPTY rAF loop: the meter must add nothing to that.
  type Counts = { layout: number; style: number; styleMs: number; layoutMs: number; scriptMs: number };
  const idle = async (p: Page): Promise<Counts> => {
    const cdp = await p.context().newCDPSession(p);
    await cdp.send("Performance.enable");
    const read = async (): Promise<Counts> => {
      const { metrics } = (await cdp.send("Performance.getMetrics")) as { metrics: Array<{ name: string; value: number }> };
      const get = (n: string): number => metrics.find((m) => m.name === n)!.value;
      return { layout: get("LayoutCount"), style: get("RecalcStyleCount"), styleMs: get("RecalcStyleDuration") * 1000, layoutMs: get("LayoutDuration") * 1000, scriptMs: get("ScriptDuration") * 1000 };
    };
    await p.waitForTimeout(300);
    const x = await read();
    await p.waitForTimeout(3000);
    const y = await read();
    return { layout: y.layout - x.layout, style: y.style - x.style, styleMs: y.styleMs - x.styleMs, layoutMs: y.layoutMs - x.layoutMs, scriptMs: y.scriptMs - x.scriptMs };
  };
  const rows: Record<"none" | "empty-raf" | "meter", Counts[]> = { none: [], "empty-raf": [], meter: [] };
  for (let round = 0; round < 3; round++) {
    for (const mode of ["none", "empty-raf", "meter"] as const) {
      const p = await page.context().newPage();
      await open(p, mode === "meter" ? "&fps=bench" : "&fps=0");
      if (mode === "empty-raf") await p.evaluate(() => { const loop = (): void => { requestAnimationFrame(loop); }; requestAnimationFrame(loop); });
      if (mode === "meter") await hud(p).call((h) => { h.pauseRepaint(); return 0; });
      rows[mode].push(await idle(p));
      await p.close();
    }
  }
  const sum = (mode: keyof typeof rows, k: keyof Counts): number => rows[mode].reduce((t, c) => t + c[k], 0);
  for (const mode of Object.keys(rows) as Array<keyof typeof rows>) {
    console.log(`PERF-RECALC ${mode} (3 rounds x 3 s idle): layouts ${sum(mode, "layout")}, style recalcs ${sum(mode, "style")}, style ${sum(mode, "styleMs").toFixed(1)} ms, layout ${sum(mode, "layoutMs").toFixed(1)} ms, script ${sum(mode, "scriptMs").toFixed(1)} ms`);
  }
  expect(sum("meter", "layout")).toBeLessThanOrEqual(sum("empty-raf", "layout") + 3);
  expect(sum("meter", "style")).toBeLessThanOrEqual(Math.ceil(sum("empty-raf", "style") * 1.05) + 3);
  await hud(page).call((h) => { h.pauseRepaint(); return 0; });
  // Nothing in the meter's own subtree changes while the repaint is stopped: the loop writes the ring and nothing else.
  const mutations = await page.evaluate(() => new Promise<number>((done) => {
    let n = 0;
    const hudEl = document.querySelector(".perf-hud")!;
    const o = new MutationObserver((list) => { for (const m of list) if (hudEl.contains(m.target)) n++; });
    o.observe(hudEl, { subtree: true, attributes: true, childList: true, characterData: true });
    setTimeout(() => { o.disconnect(); done(n); }, 3000);
  }));
  console.log("PERF-MUTATIONS in the meter subtree, 3 s, repaint paused:", mutations);
  expect(mutations).toBe(0);
  const self = await hud(page).call((h) => h.selfTime());
  console.log("PERF-SELF real frames", JSON.stringify(self));
  expect(self.meanMs).toBeLessThan(0.05);
});
