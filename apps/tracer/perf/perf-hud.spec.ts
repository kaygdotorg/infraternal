/** Unchanged frame-meter CPU and recalculation budgets, run under perf-run on the perf VM (#314). */
import { expect, test, type Page } from "playwright/test";
import { hud, open } from "../test/perf-hud-fixture";

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
