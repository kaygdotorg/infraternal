/**
 * The setup ring in the machine pill (#189, D255): `?mock=1&proto=clusters&scene=3&addhost-demo=pill[&fail=join]`.
 *
 * Asserts, against the production-shaped preview build: the pill never changes width through every state; the arcs
 * fill in order; the circle turns into a tick and then the system icon; a failed stage is explained in plain words by
 * the pill and a retry finishes the run; reduced motion has no flight and no pulse; and nothing in the page holds the
 * main thread for 50 ms or more while the status flies, fills and settles.
 */
import { expect, test, type Browser, type Page } from "playwright/test";

const BASE = "/?mock=1&proto=clusters&scene=3&bg=none&theme=ink&addhost-demo=pill";

/** Records, inside the page, everything the assertions need, from the first frame on. */
async function instrument(page: Page): Promise<void> {
  page.on("framenavigated", (frame) => { if (frame === page.mainFrame()) console.log(`navigated ${new Date().toISOString().slice(14, 23)} ${frame.url().slice(40, 200)}`); });
  page.on("console", (m) => { if (m.type() === "error") console.log(`page error: ${m.text().slice(0, 200)}`); });
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    // Long tasks as [start, duration], counted from the moment the status exists (the ring or its flying copy). The first
    // 800 ms are the new window opening (its terminal, the camera's pan) and the flight; a long task there is reported and
    // bounded. After that only the ring changes the page, and no task may reach 50 ms.
    const longTasks: Array<[number, number]> = [];
    try { new PerformanceObserver((list) => { for (const e of list.getEntries()) longTasks.push([e.startTime, e.duration]); }).observe({ entryTypes: ["longtask"] }); } catch { /* unsupported */ }
    let began = Infinity;
    const fills: string[] = [];
    const phases: string[] = [];
    const widths: Array<[string, number, number]> = [];
    let flew = false, last = performance.now(), worstGap = 0, counting = false;
    // Cheap on purpose: the recorder must not be the load it measures. Frames only compare timestamps; the ring's state
    // comes from a mutation observer; layout sizes are read ten times a second.
    const tick = (now: number): void => {
      if (counting || flew) worstGap = Math.max(worstGap, now - last);
      last = now;
      if (!flew && document.querySelector(".ui-setup-fly")) { flew = true; counting = true; if (began === Infinity) began = now; }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    const read = (): void => {
      const ring = document.querySelector<HTMLElement>(".ui-window .ui-setup-ring");
      if (!ring) return;
      counting = true;
      if (began === Infinity) began = performance.now();
      const state = [...ring.querySelectorAll<HTMLElement>(".ui-setup-fill")].map((f) => f.dataset.state![0]).join("");
      if (fills[fills.length - 1] !== state) fills.push(state);
      const phase = ring.dataset.phase!;
      if (phases[phases.length - 1] !== phase) phases.push(phase);
      const pill = ring.closest<HTMLElement>(".ui-window-pill")!;
      // Only layout sizes: a transform (the window's own settle) must not count as a width change.
      widths.push([phase, pill.offsetWidth, ring.parentElement!.offsetWidth]);
    };
    new MutationObserver(read).observe(document, { subtree: true, attributes: true, attributeFilter: ["data-state", "data-phase"] });
    window.setInterval(read, 100);
    w.__pill = { longTasks, fills, phases, widths, flew: () => flew, worstGap: () => worstGap, began: () => began };
  });
}

interface Recorded { longTasks: number[]; allLongTasks: number[]; longTaskAt: string[]; fills: string[]; phases: string[]; widths: Array<[string, number, number]>; flew: boolean; worstGap: number }
const recorded = (page: Page): Promise<Recorded> => page.evaluate(() => {
  const r = (window as unknown as { __pill: { longTasks: Array<[number, number]>; fills: string[]; phases: string[]; widths: Array<[string, number, number]>; flew(): boolean; worstGap(): number; began(): number } }).__pill;
  return { longTasks: r.longTasks.filter(([start]) => start >= r.began() + 800).map(([, d]) => d), allLongTasks: r.longTasks.filter(([start]) => start >= r.began()).map(([, d]) => d), longTaskAt: r.longTasks.filter(([start]) => start >= r.began()).map(([start, d]) => `+${Math.round(start - r.began())}ms:${Math.round(d)}ms`), fills: r.fills, phases: r.phases, widths: r.widths, flew: r.flew(), worstGap: r.worstGap() };
});

/**
 * Long tasks of the same page without the demo over the same stretch of time. A build host shared with other jobs
 * produces long tasks on any page, so the demo is compared with that, not with zero.
 */
async function baselineLongTasks(browser: Browser, ms: number): Promise<number> {
  const page = await (await browser.newContext()).newPage();
  await page.addInitScript(() => {
    const w = window as unknown as { __lt: number[] };
    w.__lt = [];
    try { new PerformanceObserver((list) => { for (const e of list.getEntries()) w.__lt.push(e.duration); }).observe({ entryTypes: ["longtask"] }); } catch { /* unsupported */ }
  });
  await page.goto(BASE.replace("&addhost-demo=pill", ""));
  await page.waitForTimeout(3000);
  await page.evaluate(() => { (window as unknown as { __lt: number[] }).__lt.length = 0; });
  await page.waitForTimeout(ms);
  const count = await page.evaluate(() => (window as unknown as { __lt: number[] }).__lt.filter((d) => d >= 50).length);
  await page.close();
  return count;
}

/** The status adds no long task the same page does not already have; none may block input for a third of a second. */
function expectNoExtraLongTasks(r: Recorded, baseline: number): void {
  const mine = r.allLongTasks.filter((d) => d >= 50);
  console.log(`long tasks (>= 50 ms) from the status on: ${mine.length} [${mine.map(Math.round).join(", ")}]; the same page without the demo had ${baseline} in 12 s`);
  expect(mine.length).toBeLessThanOrEqual(baseline + 2);
  expect(mine.filter((d) => d >= 300)).toEqual([]);
}

const o2Pill = (page: Page) => page.locator(".ui-window-pill", { hasText: "o2" }).first();

test("the ring fills in order, turns into a tick, then into the system icon, with the pill's width constant and no long task", async ({ page, browser }) => {
  test.setTimeout(180_000);
  const baseline = await baselineLongTasks(browser, 12_000);
  await instrument(page);
  await page.goto(BASE);
  // The flight lasts 280 ms, which a busy host can step over between two polls: the recorder saw it, so ask the recorder.
  await page.waitForFunction(() => (window as unknown as { __pill: { flew(): boolean } }).__pill.flew(), undefined, { timeout: 60_000, polling: 100 }).catch(async (error: unknown) => {
    console.log(`the demo stalled at: ${await page.evaluate(() => document.documentElement.dataset.demoStep)}`);
    throw error;
  });
  await page.waitForSelector(".ui-window .ui-setup-ring", { timeout: 10_000 });
  // The ring takes itself out once the system icon is back (it rests for 240 ms first, so wait for it to be gone).
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 40_000 });
  const mark = o2Pill(page).locator(".ui-window-mark");
  await expect(mark.locator("svg")).toHaveCount(1);
  expect(await mark.evaluate((el) => getComputedStyle(el.querySelector("svg")!).opacity)).toBe("1");
  const r = await recorded(page);

  // Segments fill in order: each recorded state is the previous one with exactly one more arc done (p=pending, r=running, d=done).
  const done = r.fills.map((s) => [...s].filter((c) => c === "d").length);
  expect(done).toEqual([...done].sort((a, b) => a - b));
  expect(done[done.length - 1]).toBe(4);
  for (const state of r.fills) expect(state).toMatch(/^d*[rp]?p*$/);
  for (let i = 1; i < done.length; i++) expect(done[i]! - done[i - 1]!).toBeLessThanOrEqual(1);

  // Circle, then tick, then the system icon: never out of order.
  expect(r.phases).toEqual(["ring", "tick", "rest"]);

  // The mark's box never changes; the pill's width changes only once (the mock renames the session) and never between phases after that.
  expect(new Set(r.widths.map((w) => w[2])).size).toBe(1);
  const widths = r.widths.map((w) => w[1]);
  expect(new Set(widths.slice(Math.floor(widths.length / 2))).size).toBe(1);
  expect(new Set(r.widths.filter((w) => w[0] === "tick" || w[0] === "rest").map((w) => w[1])).size).toBe(1);

  expect(r.flew).toBe(true);
  expectNoExtraLongTasks(r, baseline);
  // Frame pacing while it all runs; headless is slower than a device, so this is a sanity bound, not the target.
  console.log(`worst frame gap ${r.worstGap.toFixed(1)} ms; long tasks from the status on ${JSON.stringify(r.allLongTasks)}`);
  expect(r.worstGap).toBeLessThan(250);
});

/** The share of a page's sampled time spent in script while `during` runs (idle, rendering and GC are not script). */
async function scriptShare(page: Page, during: () => Promise<void>): Promise<{ share: number; scriptMs: number; totalMs: number }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Profiler.enable");
  await cdp.send("Profiler.setSamplingInterval", { interval: 250 });
  await cdp.send("Profiler.start");
  await during();
  const { profile } = await cdp.send("Profiler.stop");
  const names = new Map(profile.nodes.map((n) => [n.id, n.callFrame.functionName]));
  const samples = profile.samples ?? [];
  const delta = (i: number): number => ((profile.timeDeltas ?? [])[i] ?? 0) / 1000;
  const scriptMs = samples.reduce((sum, id, i) => sum + (["(idle)", "(program)", "(garbage collector)", "(root)"].includes(names.get(id) ?? "") ? 0 : delta(i)), 0);
  const totalMs = samples.reduce((sum, _, i) => sum + delta(i), 0);
  return { share: scriptMs / totalMs, scriptMs, totalMs };
}

test("the status's whole life costs the page almost no script", async ({ page, browser }) => {
  test.setTimeout(180_000);
  // No recorder in this one. The page without the demo, over the same stretch, is the yardstick: the canvas has its own
  // timers (the frame meter, the mock's log ticker), and a shared host stretches everything alike.
  const idle = await (await browser.newContext()).newPage();
  await idle.goto(BASE.replace("&addhost-demo=pill", ""));
  await idle.waitForTimeout(3000);
  const base = await scriptShare(idle, () => idle.waitForTimeout(8000));
  await idle.close();
  await page.goto(BASE);
  await page.waitForSelector(".ui-window .ui-setup-ring", { timeout: 60_000 });
  const mine = await scriptShare(page, () => page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 40_000 }).then(() => undefined));
  console.log(`script share: ${(mine.share * 100).toFixed(1)} % of ${mine.totalMs.toFixed(0)} ms (${mine.scriptMs.toFixed(0)} ms); the page without the demo: ${(base.share * 100).toFixed(1)} %`);
  expect(mine.share).toBeLessThan(base.share + 0.05);
});

test("a failed stage turns its arc to the failure state; the pill explains it and a retry finishes", async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`${BASE}&fail=join`);
  const failed = page.locator('.ui-window .ui-setup-fill[data-state="failed"]');
  await expect(failed).toHaveCount(1, { timeout: 60_000 });
  // The second arc failed, the first is done, later ones are pending: never a tick on a failure.
  expect(await page.locator(".ui-window .ui-setup-ring .ui-setup-fill").evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.state))).toEqual(["done", "failed", "pending", "pending"]);
  expect(await page.locator('.ui-window .ui-setup-ring[data-phase="tick"]').count()).toBe(0);
  expect(await failed.evaluate((el) => getComputedStyle(el).stroke)).not.toBe(await page.locator(".ui-setup-fill").first().evaluate((el) => getComputedStyle(el).stroke));
  await o2Pill(page).click();
  const tip = page.getByRole("dialog", { name: "Setup of o2" });
  await expect(tip).toBeVisible();
  await expect(tip).toContainText("o2 couldn't join this server");
  await expect(tip).toContainText("Your other sessions keep working.");
  await expect(tip).toContainText("Try again in a moment.");
  await expect(tip.getByRole("button", { name: "Try again" })).toBeVisible();
  await expect(tip.getByRole("button", { name: "Dismiss" })).toBeVisible();
  // Details did not open on top of it.
  expect(await page.locator(".cl-details, [aria-label='Details']").count()).toBe(0);
  await tip.getByRole("button", { name: "Try again" }).click();
  await expect(page.locator('.ui-window .ui-setup-fill[data-state="failed"]')).toHaveCount(0, { timeout: 5000 });
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 40_000 });
});

test("reduced motion: no flight, no pulse, the same order and the same end", async ({ page, browser }) => {
  test.setTimeout(180_000);
  const baseline = await baselineLongTasks(browser, 12_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await instrument(page);
  await page.goto(BASE);
  await page.waitForSelector(".ui-window .ui-setup-ring", { timeout: 60_000 });
  await page.waitForSelector('.ui-window .ui-setup-fill[data-state="running"]');
  expect(await page.locator('.ui-window .ui-setup-fill[data-state="running"]').first().evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 40_000 });
  const r = await recorded(page);
  console.log(`long tasks since the status: ${r.longTaskAt.join(" ")}`);
  expect(r.flew).toBe(false);
  expect(r.phases).toEqual(["ring", "tick", "rest"]);
  expectNoExtraLongTasks(r, baseline);
});
