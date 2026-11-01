/** Queue CPU and retained heap matrix runs only by explicit relay under the perf-VM lock (D256, D312). */
import { expect, test } from "playwright/test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { tracerEvidencePath } from "../test/evidence-path";
test.skip(process.env.LAYOUT_PERF !== "1", "timing and memory evidence belongs on the locked perf VM");
test("1/10/60 windows and 8192/32768 pending intents: capture, rebase, reconnect and heap multiplied by tabs", async ({ page }) => {
  test.setTimeout(180_000);
  const bundle = process.env.LAYOUT_QUEUE_BUNDLE;
  if (!bundle) throw Error("Build test/layout-queue-perf.ts on the build host and relay its bundle with LAYOUT_QUEUE_BUNDLE");
  const pages = [page, await page.context().newPage(), await page.context().newPage()];
  const source = await readFile(bundle, "utf8");
  const drivers = await Promise.all(pages.map(async (tab) => {
    await tab.goto("about:blank"); await tab.addScriptTag({ content: source });
    const cdp = await tab.context().newCDPSession(tab); await cdp.send("Performance.enable");
    return { tab, async heap(): Promise<number> {
      await cdp.send("HeapProfiler.collectGarbage");
      const { metrics } = await cdp.send("Performance.getMetrics");
      return metrics.find((row) => row.name === "JSHeapUsedSize")!.value;
    } };
  }));
  const rows: Array<Record<string, number>> = [];
  for (const windows of [1, 10, 60]) for (const queued of [8192, 32768]) {
    await Promise.all(drivers.map(async ({ tab }) => tab.evaluate(() => (globalThis as unknown as { layoutQueueProbe: { clear(): void } }).layoutQueueProbe.clear())));
    const baselines = await Promise.all(drivers.map((driver) => driver.heap()));
    const measured = await Promise.all(drivers.map(async ({ tab, heap }, index) => {
      const row = await tab.evaluate(({ windows, queued }) => (globalThis as unknown as { layoutQueueProbe: { seed(windows: number, queued: number): Record<string, number> } }).layoutQueueProbe.seed(windows, queued), { windows, queued });
      return { ...row, tab: index, retainedHeapBytes: (await heap()) - baselines[index]! };
    }));
    const actualThreeTabsBytes = measured.reduce((sum, row) => sum + row.retainedHeapBytes, 0);
    for (const row of measured) rows.push({ ...row, actualThreeTabsBytes, heapTenTabsBytes: row.retainedHeapBytes * 10 });
  }
  const dir = tracerEvidencePath("layout-queue-perf"); await mkdir(dir, { recursive: true });
  await writeFile(`${dir}/matrix.json`, JSON.stringify({ machine: hostname(), rows }, null, 2));
  // Save every measurement before asserting budgets so a slow case remains reviewable.
  for (const row of rows) {
    expect(row.retained).toBe(row.queued);
    expect(row.captureMaxMs).toBeLessThanOrEqual(16); expect(row.rebaseMs).toBeLessThanOrEqual(16); expect(row.reconnectMs).toBeLessThanOrEqual(16);
  }
});
