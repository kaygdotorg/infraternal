/**
 * Click-to-first-visible-frame of the Add host wizard on a production build (#480, D375, TASTE "Work is instant").
 *
 * The owner's rule is that an operation finishes at once and animation only presents the finished result, so the card
 * must be on screen in the first frame after the click, not after a chunk fetch and the setup behind it. This spec clicks
 * the toolbar's Add host button with a real pointer press, then samples every animation frame and reports:
 *
 *  - `firstFrameMs`: from the click's own timestamp to the first frame where the card exists and is not transparent;
 *  - the chunks requested after the click (what a cold or unwarmed open still has to fetch);
 *  - long tasks that started after the click.
 *
 * Two loads at two sizes: **cold** (the click lands the moment the toolbar button exists, before the page went idle) and
 * **warm** (the page has been idle for a while, so idle warming has had its chance). Each runs against the direct
 * backend (local paint cost only) and through the latency proxy (what a real link adds). Budget: warm and direct must
 * land within one 120 Hz frame budget of 16 ms (D375). Cold and proxied numbers are reported for the record.
 *
 * Perf harness only (it asserts elapsed time): run it through `perf-run`, see README.md. For a before/after on a
 * development VM, pass `TRACER_ADDHOST_REPORT_ONLY=1` to print the table without asserting.
 */
import { test, expect, type Browser, type Page } from "playwright/test";
import { writeFileSync } from "node:fs";
import { tracerEvidencePath } from "../test/evidence-path";

/** One measured open. */
interface Sample { firstFrameMs: number; fetched: string[]; longTasks: number; }

/** What the page-side recorder collects between the click and the first visible frame. */
interface Recording { t0: number; frames: Array<{ ts: number; has: boolean; opacity: number }>; resources: Array<{ name: string; start: number; end: number }>; longTasks: number[]; }

/** Desktop and phone viewport sizes measured independently. */
const SIZES = [{ name: "1440x900", width: 1440, height: 900 }, { name: "393x852", width: 393, height: 852 }] as const;
/** Number of first-frame observations per viewport and cache state. */
const SAMPLES = Number(process.env.TRACER_ADDHOST_SAMPLES ?? "5");
/** Whether this run records observations without enforcing its budget. */
const reportOnly = process.env.TRACER_ADDHOST_REPORT_ONLY === "1";
/** Loopback backend port used to separate direct and relayed observations. */
const backendPort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
/** Direct and relayed addresses for the same test server. */
const ORIGINS = { direct: `http://localhost:${backendPort}`, proxied: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` } as const;

/** Installs the recorder before the page's own scripts run, so no frame between click and card is missed. */
async function installRecorder(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const rec: Recording = { t0: 0, frames: [], resources: [], longTasks: [] };
    (window as unknown as { __ah: Recording }).__ah = rec;
    try { new PerformanceObserver((list) => { for (const e of list.getEntries()) rec.resources.push({ name: e.name, start: e.startTime, end: (e as PerformanceResourceTiming).responseEnd }); }).observe({ type: "resource" }); } catch { /* unsupported */ }
    try { new PerformanceObserver((list) => { for (const e of list.getEntries()) rec.longTasks.push(e.startTime); }).observe({ type: "longtask" }); } catch { /* unsupported */ }
    document.addEventListener("click", (event) => {
      if (rec.t0 || !(event.target as Element | null)?.closest?.("[aria-label^='Add host'], [data-id='add']")) return;
      rec.t0 = event.timeStamp;
      const tick = (ts: number): void => {
        const card = document.querySelector(".ah-float");
        rec.frames.push({ ts, has: card !== null, opacity: card ? Number(getComputedStyle(card).opacity) : 0 });
        if (rec.frames.length < 90 && !(card && Number(getComputedStyle(card).opacity) > 0)) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }, true);
  });
}

/** Opens the clusters canvas on a freshly reset double and returns once the Add host button can be clicked. */
async function openCanvas(page: Page, origin: string): Promise<void> {
  await page.request.post(`${origin}/__mock/reset`, { maxRetries: 1 });
  await page.request.post(`${origin}/__mock/bootstrap/reset`, { maxRetries: 1 });
  await page.goto(`${origin}/?mock=1&proto=clusters&scene=3&theme=ink&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
}

/** Presses the real Add host control (toolbar button; the palette row on a phone-sized toolbar) with a mouse click. */
async function pressAddHost(page: Page): Promise<void> {
  const button = page.getByRole("button", { name: /^Add host/ }).first();
  await button.waitFor({ state: "visible", timeout: 45_000 });
  const box = (await button.boundingBox())!;
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}

/** One open in a fresh browser context (an empty HTTP cache), warm or cold. */
async function measure(browser: Browser, origin: string, size: (typeof SIZES)[number], warm: boolean): Promise<Sample> {
  const context = await browser.newContext({ viewport: { width: size.width, height: size.height } });
  const page = await context.newPage();
  try {
    await installRecorder(page);
    await openCanvas(page, origin);
    // sleep: warm means the page has been idle long enough for idle warming to finish (the mount's idle timeout is 1 s).
    if (warm) { await page.waitForLoadState("networkidle"); await page.waitForTimeout(4000); }
    await pressAddHost(page);
    await page.waitForFunction(() => { const r = (window as unknown as { __ah: Recording }).__ah; return r.t0 > 0 && r.frames.some((f) => f.has && f.opacity > 0); }, undefined, { timeout: 10_000 });
    const rec = await page.evaluate(() => (window as unknown as { __ah: Recording }).__ah);
    const first = rec.frames.find((f) => f.has && f.opacity > 0)!;
    return {
      firstFrameMs: first.ts - rec.t0,
      fetched: rec.resources.filter((r) => r.start >= rec.t0 && r.name.endsWith(".js")).map((r) => `${r.name.split("/").pop()} +${(r.end - rec.t0).toFixed(0)}ms`),
      longTasks: rec.longTasks.filter((t) => t >= rec.t0).length,
    };
  } finally { await context.close(); }
}

/** Returns the middle sorted observation for the summary report. */
const median = (values: number[]): number => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
/** Report lines collected across all measured scenarios. */
const rows: string[] = [];

for (const size of SIZES) {
  for (const [originName, origin] of Object.entries(ORIGINS)) {
    for (const warm of [false, true]) {
      test(`Add host first frame: ${size.name} ${originName} ${warm ? "warm" : "cold"}`, async ({ browser }) => {
        test.setTimeout(180_000);
        const samples: Sample[] = [];
        for (let i = 0; i < SAMPLES; i += 1) samples.push(await measure(browser, origin, size, warm));
        const times = samples.map((s) => s.firstFrameMs);
        const row = `${size.name} | ${originName} | ${warm ? "warm" : "cold"} | median ${median(times).toFixed(1)} ms | all ${times.map((t) => t.toFixed(0)).join("/")} | fetched after click: ${[...new Set(samples.flatMap((s) => s.fetched.map((f) => f.split(" ")[0]!)))].length} chunks | long tasks ${samples.reduce((n, s) => n + s.longTasks, 0)}`;
        rows.push(row);
        console.log(row);
        writeFileSync(tracerEvidencePath("addhost-open.txt"), `${rows.join("\n")}\n`);
        if (!reportOnly && warm && originName === "direct") expect(median(times)).toBeLessThanOrEqual(16);
      });
    }
  }
}
