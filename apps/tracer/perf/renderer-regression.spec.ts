/** Paired 50 MB throughput budget, run under perf-run on the perf VM (#314). */
import { expect, test } from "playwright/test";

test("predictive echo keeps 50 MB output throughput within five percent", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  const context = page.context();
  const fixtureName = "behemoth.txt";
  const fixtureBytes = 50_000_000;
  const rates = new Map<boolean, number[]>([[false, []], [true, []]]);

  for (let sample = 0; sample < 3; sample += 1) {
    const order = sample % 2 === 0 ? [false, true] as const : [true, false] as const;
    for (const predictive of order) {
      await page.goto("about:blank");
      await page.waitForTimeout(100);
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      await page.goto(predictive ? "/?mock=1&predict=1" : "/?mock=1");
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), {
        timeout: 30_000,
      }).toBe(true);
      if (predictive) {
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0))
          .toBeGreaterThan(60);
      }
      await page.setViewportSize({ width: 1440, height: 900 });
      const startedAt = Date.now();
      const response = await context.request.post("/__mock/fixture", { data: { name: fixtureName } });
      expect(response.status()).toBe(200);
      await expect.poll(async () => BigInt(await page.evaluate(
        () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
      )), { timeout: 5 * 60_000 }).toBeGreaterThanOrEqual(BigInt(fixtureBytes));
      const elapsedMs = Date.now() - startedAt;
      const throughput = fixtureBytes / elapsedMs / 1000;
      rates.get(predictive)?.push(throughput);
      console.log(
        `METRIC name=browser_bulk_output_throughput_${predictive ? "prediction_on" : "prediction_off"} ` +
          `source=tracer-production-build bytes=${fixtureBytes} sample=${sample + 1} elapsed_ms=${elapsedMs} ` +
          `throughput_mbps=${throughput.toFixed(2)}`,
      );
    }
  }

  const off = rates.get(false)!.sort((left, right) => left - right);
  const on = rates.get(true)!.sort((left, right) => left - right);
  const offMedian = percentile(off, 0.5);
  const onMedian = percentile(on, 0.5);
  const regressionPercent = (onMedian / offMedian - 1) * 100;
  console.log(
    `METRIC name=browser_bulk_output_throughput_delta source=tracer-production-build n=3 ` +
      `off_median_mbps=${offMedian.toFixed(2)} on_median_mbps=${onMedian.toFixed(2)} ` +
      `change_percent=${regressionPercent.toFixed(2)} budget_percent=-5 ` +
      `result=${regressionPercent >= -5 ? "PASS" : "FAIL"}`,
  );
  expect(onMedian).toBeGreaterThanOrEqual(offMedian * 0.95);
});

function percentile(sorted: number[], fraction: number): number {
  const rank = Math.max(0, Math.ceil(sorted.length * fraction) - 1);
  return sorted[rank] ?? 0;
}
