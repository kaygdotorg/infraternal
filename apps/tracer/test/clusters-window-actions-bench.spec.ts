/**
 * Layout cost of one window action with 54 windows on the canvas (D212; the budget is 8 ms of layout work per action,
 * TASTE and #121). The timer wraps the synchronous part of the action: the model and DOM change, the layout is read
 * back and settled. The droplet and the glide run after it, on the compositor and in animation frames, and are not
 * counted here. The numbers are printed so the report carries them.
 */
import { expect, test, type Page } from "playwright/test";
import { loadavg, cpus } from "node:os";

const VIEW = '.cl[data-view="console"]';
const BUDGET_MS = 8;

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  // A press on the window makes it the active one, which the window actions act on.
  await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

test("one window action with 54 windows costs at most 8 ms of layout work", async ({ page }) => {
  test.setTimeout(300_000);
  await boot(page);
  // Fill the Console with 54 windows: each new window right opens a new shell, and it becomes the active one.
  await page.evaluate(() => {
    for (let i = 0; i < 53; i++) window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } }));
  });
  await page.waitForTimeout(800);
  const n = await page.evaluate((view) => document.querySelectorAll(`${view} .ui-window`).length, VIEW);
  expect(n).toBeGreaterThanOrEqual(54);

  const actions = ["canvas:split:right", "canvas:split:down", "canvas:new:right", "canvas:new:below"] as const;
  const results: Record<string, number[]> = {};
  for (const action of actions) results[action] = [];
  for (let round = 0; round < 5; round++) {
    for (const action of actions) {
      // Each measured action starts from a window that has its column to itself: an unmeasured new window right
      // makes one. Otherwise a split right after a split down would be refused, and the timer would measure a refusal.
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } })));
      await page.waitForTimeout(500);
      // The same event the palette and the key handlers send: the timer covers the handler's synchronous work.
      const ms = await page.evaluate((a) => {
        const t = performance.now();
        window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "pointer" } }));
        return performance.now() - t;
      }, action);
      results[action]!.push(ms);
      // Let the droplet and the glide finish before the next one (they are not part of the measured work).
      await page.waitForTimeout(900);
    }
  }
  const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
  const summary = Object.fromEntries(actions.map((a) => [a, { median: Number(median(results[a]!).toFixed(2)), max: Number(Math.max(...results[a]!).toFixed(2)) }]));
  console.log(`d212 layout work at ${n}+ windows (ms, median / max over 5 rounds):`, JSON.stringify(summary));
  // The budget is asserted where the numbers mean something (the perf VM, D122): on a loaded shared host the same
  // code measures 1.5 to 2.5 times higher. `D212_BUDGET=1` turns the assertion on; the numbers are printed either way.
  if (process.env.D212_BUDGET === "1") for (const action of actions) expect(median(results[action]!), `${action} median`).toBeLessThanOrEqual(BUDGET_MS);
});

/**
 * D212 at 57 windows: a split right and a split down inside a stacked group, and the new window right after it (the whole
 * group is one grid, so these are the costs the group adds). Host load is recorded with each run, since a shared host
 * measures higher than a quiet one (see the note above).
 */
test("the group actions cost at most 8 ms of layout work with 57 windows", async ({ page }) => {
  test.setTimeout(300_000);
  await boot(page);
  await page.evaluate(() => {
    for (let i = 0; i < 56; i++) window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } }));
  });
  await page.waitForTimeout(800);
  const n = await page.evaluate((view) => document.querySelectorAll(`${view} .ui-window`).length, VIEW);
  expect(n).toBeGreaterThanOrEqual(57);
  const load = { before: loadavg()[0]!.toFixed(2), cpus: cpus().length };
  const measure = (action: string): Promise<number> => page.evaluate((a) => {
    const t = performance.now();
    window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "pointer" } }));
    return performance.now() - t;
  }, action);
  const results: Record<string, number[]> = { "canvas:split:right (in a group)": [], "canvas:split:down (in a group)": [] };
  for (let round = 0; round < 5; round++) {
    // A fresh stacked column for each round: split down the active window, then split right the window just made.
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } })));
    await page.waitForTimeout(500);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:down", source: "pointer" } })));
    // A split leaves the new window active, so the next action acts on the window that was just made.
    results["canvas:split:right (in a group)"]!.push(await measure("canvas:split:right"));
    await page.waitForTimeout(900);
    results["canvas:split:down (in a group)"]!.push(await measure("canvas:split:down"));
    await page.waitForTimeout(900);
  }
  const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
  const summary = Object.fromEntries(Object.entries(results).map(([a, xs]) => [a, { median: Number(median(xs).toFixed(2)), max: Number(Math.max(...xs).toFixed(2)) }]));
  console.log(`d212 group layout work at ${n}+ windows (ms, median / max over 5 rounds), load ${JSON.stringify(load)} after ${loadavg()[0]!.toFixed(2)}:`, JSON.stringify(summary));
  if (process.env.D212_BUDGET === "1") for (const [a, xs] of Object.entries(results)) expect(median(xs), `${a} median`).toBeLessThanOrEqual(BUDGET_MS);
});

