/**
 * The two D375 rows only a browser can measure outside the terminal scenario: rendering at 10 MB/s and first paint on a
 * phone [D375, D41].
 *
 * These run only inside `scripts/verify latency` (which sets `INFRATERNAL_LATENCY_PROFILE=1`) and print `METRIC
 * name=d375_*` rows; like the rest of the functional suite they never assert speed (#314). The report at the end of the
 * latency profile gates the rows.
 *
 * - Rendering: Chromium normally paces animation frames to the display (60 Hz headless), which would cap any result at
 *   60 fps. This file launches its browser with the frame-rate limit and vsync off, so a frame comes as soon as the
 *   previous one is done and the interval measures the real cost of a frame. The row is the frame rate held for 99% of
 *   frames (1000 / p99 interval) while the terminal takes 10 MB/s; `idle_fps` shows the uncapped rate before the load,
 *   so a run where the flags had no effect is visible.
 * - First paint: a phone-sized page with the CPU slowed 4x, served directly (no injected delay), as the perf suite's
 *   desktop first-paint check does. The row is the p99 first-contentful-paint over fresh pages.
 */
import { expect, test } from "playwright/test";
import { d375Row, FIRST_PAINT_MS, PHONE_CPU_SLOWDOWN, RENDER_FPS } from "./latency-targets";

test.skip(process.env.INFRATERNAL_LATENCY_PROFILE !== "1", "runs only in scripts/verify latency");
test.use({ launchOptions: { args: ["--disable-renderer-backgrounding", "--disable-frame-rate-limit", "--disable-gpu-vsync"] } });

test("rendering under 10 MB/s output, frame rate uncapped", async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  const measured = await page.evaluate(async () => {
    /** Collects animation-frame intervals until `stop()`; the first interval (from the call) is dropped. */
    const frames = (): { stop: () => number[] } => {
      const intervals: number[] = [];
      let previous: number | undefined;
      let running = true;
      const tick = (at: number): void => {
        if (previous !== undefined) intervals.push(at - previous);
        previous = at;
        if (running) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
      return { stop: () => { running = false; return intervals; } };
    };
    const idle = frames();
    // sleep: a fixed one-second window of idle frames is the measurement itself, not a wait for a state.
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    const idleIntervals = idle.stop();
    const loaded = frames();
    const bench = await window.__tracerTestDouble?.benchmarkOutputAt10MBps();
    return { idleIntervals, loadedIntervals: loaded.stop(), bench };
  });
  expect(measured.bench).toBeDefined();
  const sorted = measured.loadedIntervals.slice().sort((left, right) => left - right);
  expect(sorted.length).toBeGreaterThan(10);
  const p99Interval = percentile(sorted, 0.99);
  const idleFps = measured.idleIntervals.length / (measured.idleIntervals.reduce((sum, ms) => sum + ms, 0) / 1000);
  const meanFps = sorted.length / (sorted.reduce((sum, ms) => sum + ms, 0) / 1000);
  const bench = measured.bench!;
  console.log(d375Row({
    key: "render_10mbps", source: "tracer-production-build", n: sorted.length, value: 1000 / p99Interval, unit: "fps",
    target: RENDER_FPS, higherIsBetter: true,
    extra: `p99_frame_ms=${p99Interval.toFixed(2)} mean_fps=${meanFps.toFixed(1)} idle_fps=${idleFps.toFixed(1)} ` +
      `effective_mbps=${(bench.bytes / bench.elapsedMs / 1000).toFixed(2)} write_cpu_ms=${bench.writeCpuMs.toFixed(1)}`,
  }).line);
});

test("first paint on a phone-class CPU", async ({ browser }) => {
  test.setTimeout(180_000);
  // Direct backend: the latency relay listens on TRACER_TEST_PORT and the backend one port above it.
  const backendPort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
  const localOrigin = `http://localhost:${backendPort}`;
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
  const firstPaints: number[] = [];
  try {
    for (let index = 0; index < 20; index += 1) {
      // A fresh page each time: Chromium may reuse an unchanged compositor frame on reload.
      const sample = await context.newPage();
      const cdp = await context.newCDPSession(sample);
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: PHONE_CPU_SLOWDOWN });
      await sample.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
      await sample.goto(localOrigin);
      await expect(sample.locator("#login-passkey")).toBeVisible();
      firstPaints.push(await sample.evaluate(() =>
        performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? Number.POSITIVE_INFINITY));
      await sample.close();
    }
  } finally {
    await context.close();
  }
  const sorted = firstPaints.sort((left, right) => left - right);
  console.log(d375Row({
    key: "first_paint_phone", source: "tracer-production-build", n: sorted.length, value: percentile(sorted, 0.99),
    unit: "ms", target: FIRST_PAINT_MS,
    extra: `p50_ms=${percentile(sorted, 0.5).toFixed(2)} cpu_slowdown=${PHONE_CPU_SLOWDOWN} viewport=393x852 rtt_ms=0`,
  }).line);
});

/** Nearest-rank percentile of an ascending array (0 when empty). */
function percentile(sorted: number[], fraction: number): number {
  const rank = Math.max(0, Math.ceil(sorted.length * fraction) - 1);
  return sorted[rank] ?? 0;
}
