// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The first use of code that loads on demand (D188, #322): the canvas fetches these modules when the browser is idle, but a
 * person can act before they have arrived. Each test holds the module's response, does the thing, checks that nothing broke or
 * moved on its own, then lets the module through and checks the action lands. The chunk is found in the build by a string only
 * that module contains, so no chunk name is written here.
 *
 * Functional only: the times are logged for the issue, never asserted (speed is measured on the perf VM).
 */
import { readdirSync, readFileSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

// The app's service worker (offline-cache.ts) would answer chunk requests before `page.route` sees them.
test.use({ serviceWorkers: "block" });

type Probe = {
  views(): Array<{ id: string; x: number; y: number; w: number; h: number }>;
  canvasLock(): { view: string };
};
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

const dist = process.env.TRACER_DIST ?? "dist";
/** The one chunk of the build that contains `marker`. */
function chunkWith(marker: string): string {
  const hits = readdirSync(dist).filter((name) => /^chunk-[0-9a-z]{8}\.js$/.test(name) && readFileSync(`${dist}/${name}`, "utf8").includes(marker));
  expect(hits, `exactly one chunk holds ${marker}`).toHaveLength(1);
  return hits[0]!;
}

/** Holds a chunk's request until `release()`; the fetch itself starts then, so the wait includes the real transfer. */
async function hold(page: Page, file: string): Promise<{ release(): void }> {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route(`**/${file}`, async (route) => { await gate; await route.continue(); });
  return { release };
}

async function open(page: Page, scene: number): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=mocha&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  await page.waitForTimeout(1500); // the camera comes to rest; the idle preloads of every other module have gone
}

test("a split asked for before its module has arrived lands when it does", async ({ page }) => {
  test.setTimeout(60_000);
  const held = await hold(page, chunkWith("dataset.split"));
  await open(page, 1);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
  const count = (): Promise<number> => page.evaluate(() => document.querySelectorAll('.cl[data-view="console"] .ui-window').length);
  const before = await count();
  await page.keyboard.down("Control"); await page.keyboard.down("Shift");
  await page.keyboard.press("KeyD");
  await page.keyboard.up("Shift"); await page.keyboard.up("Control");
  await page.waitForTimeout(500);
  expect(await count(), "nothing happens on its own while the module is on its way").toBe(before);
  const t0 = Date.now();
  held.release();
  await expect.poll(count).toBe(before + 1);
  console.log(`split asked before its module arrived: ${Date.now() - t0} ms from the transfer starting to the new window`);
  expect(await count(), "one press is one split").toBe(before + 1);
});

test("the palette opened before its rows have arrived is filled in when they do, and stays open", async ({ page }) => {
  test.setTimeout(60_000);
  const held = await hold(page, chunkWith("Unlink team layout to edit"));
  await open(page, 1);
  await page.keyboard.press("Control+Shift+K");
  const row = page.getByText("Go to Console").first();
  await page.waitForTimeout(500);
  await expect(row, "no canvas rows before the module is there").toHaveCount(0);
  const t0 = Date.now();
  held.release();
  await expect(row).toBeVisible();
  console.log(`palette rows after an open palette waited for them: ${Date.now() - t0} ms`);
  await page.keyboard.type("lock");
  await expect(page.getByText("Canvas lock off").first()).toBeVisible();
});

test("a view's label still flies to the view before the pointer module has arrived, and a drag continues when it does", async ({ page }) => {
  test.setTimeout(60_000);
  const held = await hold(page, chunkWith("cl-summary-pick"));
  await open(page, 6);
  const label = async () => (await page.locator('.cl[data-view="containers"] .cl-label').boundingBox())!;
  // A tap flies, with the module held.
  const l0 = await label();
  await page.mouse.click(l0.x + 40, l0.y + 12);
  await expect.poll(() => probe(page, (p) => p.canvasLock().view)).toBe("containers");
  // A hover shows no card yet.
  await page.mouse.move(5, 5);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { overview(): void } }).__tracerClusters.overview());
  await page.waitForTimeout(1500);
  const l1 = await label();
  await page.mouse.move(l1.x + 40, l1.y + 12);
  await page.waitForTimeout(400);
  await expect(page.locator(".cl-summary[data-open='true']")).toHaveCount(0);
  // A drag begun before the module arrives continues from where the pointer is when it does.
  const before = (await probe(page, (p) => p.views())).find((v) => v.id === "containers")!;
  await page.mouse.down();
  await page.mouse.move(l1.x + 60, l1.y - 150, { steps: 6 });
  const t0 = Date.now();
  held.release();
  await page.waitForTimeout(800);
  await page.mouse.move(l1.x + 60, l1.y - 330, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(1500);
  const views = await probe(page, (p) => p.views());
  const after = views.find((v) => v.id === "containers")!;
  console.log(`label drag begun before the module arrived: moved (${after.x - before.x}, ${after.y - before.y}); released ${Date.now() - t0 - 800} ms after the transfer started`);
  expect(after.y).toBeLessThan(before.y);
  for (const v of views) { expect(Math.abs(v.x / 120 - Math.round(v.x / 120))).toBeLessThan(0.02); expect(Math.abs(v.y / 120 - Math.round(v.y / 120))).toBeLessThan(0.02); }
  // With the module in, the hover card shows.
  await page.mouse.move(5, 5);
  await page.mouse.move((await label()).x + 40, (await label()).y + 12);
  await expect(page.locator(".cl-summary[data-open='true']")).toHaveCount(1);
});

test("the modules are fetched by the page itself when it is idle, without anyone asking", async ({ page }) => {
  test.setTimeout(60_000);
  const markers = { split: "dataset.split", "palette rows": "Unlink team layout to edit", "view pointer": "cl-summary-pick", "authority control": "Unlock host connections" };
  const files = Object.fromEntries(Object.entries(markers).map(([name, marker]) => [name, chunkWith(marker)]));
  await open(page, 1);
  const seen = await page.evaluate(() => performance.getEntriesByType("resource").map((e) => ({ name: e.name.split("/").at(-1)!, start: Math.round(e.startTime), end: Math.round((e as PerformanceResourceTiming).responseEnd) })));
  const shown: string[] = [];
  for (const [name, file] of Object.entries(files)) {
    const entry = seen.find((e) => e.name === file);
    expect(entry, `${name} (${file}) was fetched without being asked`).toBeTruthy();
    shown.push(`${name} requested at ${entry!.start} ms, arrived ${entry!.end} ms`);
  }
  console.log(`idle preloads, ms after navigation start: ${shown.join("; ")}`);
});
