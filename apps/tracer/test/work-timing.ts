/**
 * Work timing of the preview's user operations (not a spec: run it by hand).
 *
 *   bun test/work-timing.ts            # 1x CPU
 *   THROTTLE=4 N=12 bun test/work-timing.ts
 *
 * Needs the mock server on TRACER_PREVIEW (default http://localhost:4796) serving the production build.
 * Each operation is repeated N times in a page with reduced motion on, so animations do not spread the
 * work over frames; the table gives, for each, the main-thread time that our own code costs (script plus
 * style plus layout, from the Chrome DevTools Performance metrics) and the whole task time including
 * commit and paint, as p50 / p95, with the number of long tasks (> 50 ms). An idle row is the noise floor.
 * The work of an operation is measured from the input event until 160 ms later; the font row "cold" excludes
 * the network wait because the metrics count only main-thread time. Target: our work <= 16 ms, no long task.
 */
import { chromium } from "playwright";

const origin = process.env.TRACER_PREVIEW ?? "http://localhost:4796";
const THROTTLE = Number(process.env.THROTTLE ?? "1");
const N = Number(process.env.N ?? "12");
const tabs = ["connection", "session", "machine"];
let tabIndex = 0, activation = 0;

const browser = await chromium.launch({ args: ["--disable-renderer-backgrounding"] });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
const page = await context.newPage();
await page.goto(`${origin}/?mock=1&proto=windows&theme=ink&bg=none&fixture=none`);
await page.waitForTimeout(3500);
const cdp = await context.newCDPSession(page);
await cdp.send("Performance.enable");
await cdp.send("Emulation.setCPUThrottlingRate", { rate: THROTTLE });
await page.evaluate(() => {
  (window as unknown as { __long: number[] }).__long = [];
  new PerformanceObserver((list) => { for (const entry of list.getEntries()) (window as unknown as { __long: number[] }).__long.push(entry.duration); }).observe({ entryTypes: ["longtask"] });
});

type Sample = { task: number; code: number };
const results: Record<string, { samples: Sample[]; long: number }> = {};
const metrics = async (): Promise<Map<string, number>> => new Map((await cdp.send("Performance.getMetrics")).metrics.map((metric) => [metric.name, metric.value]));
const delta = (a: Map<string, number>, b: Map<string, number>): Sample => {
  const d = (name: string): number => ((b.get(name) ?? 0) - (a.get(name) ?? 0)) * 1000;
  return { task: d("TaskDuration"), code: d("ScriptDuration") + d("LayoutDuration") + d("RecalcStyleDuration") };
};
const longTasks = (): Promise<number> => page.evaluate(() => (window as unknown as { __long: number[] }).__long.filter((duration) => duration > 50).length);
const resetLong = (): Promise<void> => page.evaluate(() => { (window as unknown as { __long: number[] }).__long.length = 0; });
const closeAll = async (): Promise<void> => { await page.keyboard.press("Escape"); await page.keyboard.press("Escape"); };

async function measure(label: string, action: () => Promise<void>, setup?: () => Promise<void>): Promise<void> {
  const samples: Sample[] = [];
  let long = 0;
  for (let index = 0; index < N; index++) {
    if (setup) await setup();
    await page.waitForTimeout(250);
    await resetLong();
    const before = await metrics();
    await action();
    await page.waitForTimeout(160);
    samples.push(delta(before, await metrics()));
    long += await longTasks();
  }
  results[label] = { samples, long };
}

{
  const samples: Sample[] = [];
  for (let index = 0; index < N; index++) { const before = await metrics(); await page.waitForTimeout(160); samples.push(delta(before, await metrics())); }
  results["(idle 160 ms, noise floor)"] = { samples, long: 0 };
}
await measure("palette: open (Ctrl+K)", () => page.keyboard.press("Control+k"), closeAll);
await measure("palette: filter (one keystroke)", () => page.locator("#palette-input").pressSequentially("t"), async () => { await page.locator("#palette-input").fill(""); });
await closeAll();
let theme = "paper";
await measure("theme switch (Enter on the row)", () => page.keyboard.press("Enter"), async () => {
  theme = theme === "paper" ? "ink" : "paper";
  await closeAll(); await page.keyboard.press("Control+k"); await page.locator("#palette-input").fill(`theme ${theme}`);
});
let font = "geist";
await measure("font switch, warm (Enter on the row)", () => page.keyboard.press("Enter"), async () => {
  font = font === "geist" ? "maple" : "geist";
  await closeAll(); await page.keyboard.press("Control+k"); await page.locator("#palette-input").fill(font); await page.waitForTimeout(150);
});
{
  const samples: Sample[] = [];
  for (const name of ["jetbrains", "commit", "monaspace", "plex", "cascadia", "fira", "source"]) {
    await closeAll(); await page.keyboard.press("Control+k"); await page.locator("#palette-input").fill(name); await page.waitForTimeout(250);
    await resetLong();
    const before = await metrics();
    await page.keyboard.press("ArrowDown"); // selecting the row previews the font: fetch, decode, apply
    await page.waitForTimeout(900);
    samples.push(delta(before, await metrics()));
    await page.keyboard.press("Escape");
  }
  results["font switch, cold (first selection; fetch excluded)"] = { samples, long: await longTasks() };
}
await closeAll();
await measure("info popover: open (click pill)", () => page.locator(".ui-window-pill").nth(1).click(), closeAll);
await measure("info popover: switch tab", () => page.locator(`.canvas-popover .ui-tab[data-tab='${tabs[tabIndex++ % 3]}']`).click(), async () => {
  if (!(await page.locator(".canvas-popover").count())) await page.locator(".ui-window-pill").nth(1).click();
});
await closeAll();
await page.locator("#sidebar-toggle").click(); await page.waitForTimeout(300);
await measure("settings/about: open (gear)", () => page.locator(".ui-sidebar-settings").click(), async () => {
  if (await page.locator(".ui-settings").count()) await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
});
if (await page.locator(".ui-settings").count()) await page.keyboard.press("Escape");
await page.locator("#sidebar-toggle").click(); await page.waitForTimeout(300);
await measure("lock/unlock (Ctrl+Shift+L)", () => page.keyboard.press("Control+Shift+KeyL"));
await measure("sidebar: open", () => page.locator("#sidebar-toggle").click(), async () => {
  if (await page.locator("#sidebar").isVisible()) await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(200);
});
await measure("sidebar: close", () => page.locator("#sidebar-toggle").click(), async () => {
  if (!(await page.locator("#sidebar").isVisible())) await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(200);
});
await measure("window activation (click an inactive window)", () => page.locator(".ui-window").nth(activation++ % 2 === 0 ? 1 : 0).locator(".ui-window-body").click({ position: { x: 100, y: 200 } }));
let direction = 0;
await measure("window resize: commit (release after a drag)", () => page.mouse.up(), async () => {
  const box = (await page.locator(".ui-window").first().boundingBox())!;
  await page.mouse.move(box.x + box.width - 3, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width - 3 + (direction++ % 2 ? 40 : -40), box.y + box.height / 2, { steps: 4 });
});

const percentile = (values: number[], p: number): number => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * p))]!;
console.log(`| operation (CPU ${THROTTLE}x, n=${N}) | our work p50 / p95 ms | whole task p50 / p95 ms | long tasks |\n|---|---|---|---|`);
for (const [label, { samples, long }] of Object.entries(results)) {
  const code = samples.map((sample) => sample.code), task = samples.map((sample) => sample.task);
  console.log(`| ${label} | ${percentile(code, 0.5).toFixed(1)} / ${percentile(code, 0.95).toFixed(1)} | ${percentile(task, 0.5).toFixed(1)} / ${percentile(task, 0.95).toFixed(1)} | ${long} |`);
}
await browser.close();
