/**
 * Opt-in per-key cost bench for predictive local echo [#50, D128].
 *
 * The latency probe measures 20 keys, so its "p99" is the largest of 20 samples and mostly shows one-off jitter.
 * This bench types N keys (`TRACER_PREDICT_KEYS`, for example 400; unset skips it) with human spacing of 60-120 ms
 * and backspace bursts, reads the prediction work of every key, and explains each key slower than 2 ms:
 *   first-key       the first key of the run (after the idle warm-up)
 *   after-layout    one of the first 3 keys after a viewport resize
 *   burst-start     the overlay was not showing before the key (host cursor is hidden again, row repainted)
 *   gc              the JS heap shrank during or since the previous key (heap sizes from performance.memory)
 *   longtask        a PerformanceObserver 'longtask' overlaps the key
 *   backspace       the key was a DEL
 *   unexplained     none of the above
 * A CPU profile of the whole run (Chrome DevTools protocol, 50 us sampling) is cut into the time windows of the
 * slow keys, and the top self-time functions inside them are printed, next to the same for all keys.
 * `TRACER_PREDICT_PROFILE=0` skips the profile (sampling slows and deoptimises the page, which inflates the first keys).
 * Build with `TRACER_BUILD_READABLE=1` to keep function names in the profile. `TRACER_PREDICT_BENCH_OUT` names a JSON file for the raw per-key records.
 */
import { writeFileSync } from "node:fs";
import { expect, test } from "playwright/test";

const keyCount = Number(process.env.TRACER_PREDICT_KEYS ?? "0");
const SLOW_MS = 2;
const profiling = process.env.TRACER_PREDICT_PROFILE !== "0";

interface KeyRecord {
  index: number;
  key: string;
  cost: number;
  t0: number;
  t1: number;
  heapBefore: number;
  heapAfter: number;
  overlayBefore: boolean;
  afterLayout: boolean;
}

function percentile(sorted: number[], fraction: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * fraction + 0.5))] ?? 0;
}

test.skip(!(keyCount > 0), "set TRACER_PREDICT_KEYS=400 to run the per-key cost bench");

test(`predictive echo cost per key over ${keyCount} keys`, async ({ page, context }) => {
  test.setTimeout(120_000 + keyCount * 400);
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.addInitScript(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  // A person's first key comes well after the idle warm-up.
  await page.waitForTimeout(600);

  await page.evaluate(() => {
    const w = window as unknown as { __longtasks: Array<[number, number]> };
    w.__longtasks = [];
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) w.__longtasks.push([entry.startTime, entry.startTime + entry.duration]);
    }).observe({ type: "longtask", buffered: true });
  });
  const cdp = await context.newCDPSession(page);
  if (profiling) {
    await cdp.send("Profiler.enable");
    await cdp.send("Profiler.setSamplingInterval", { interval: 50 });
    await cdp.send("Profiler.start");
  }
  const profileStartedAt = await page.evaluate(() => performance.now());

  // Keys: runs of 28 letters, then a burst of 3-6 DELs and a retype, so rows stay short.
  const letters = "etaoinshrdlucmfwypvbgkjqxz";
  const plan: string[] = [];
  let seed = 12345;
  const random = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  while (plan.length < keyCount) {
    for (let index = 0; index < 28 && plan.length < keyCount; index += 1) plan.push(letters[Math.floor(random() * letters.length)]!);
    const burst = 3 + Math.floor(random() * 4);
    for (let index = 0; index < burst && plan.length < keyCount; index += 1) plan.push("\x7f");
    for (let index = 0; index < burst - 1 && plan.length < keyCount; index += 1) plan.push(letters[Math.floor(random() * letters.length)]!);
  }

  const records: KeyRecord[] = [];
  const chunk = Math.ceil(keyCount / 4);
  for (let from = 0; from < keyCount; from += chunk) {
    const keys = plan.slice(from, from + chunk);
    const afterLayout = from > 0;
    if (afterLayout) {
      // A resize invalidates the overlay geometry; give the idle warm-up the time a person would.
      await page.setViewportSize({ width: 1000 - 40 * (from / chunk), height: 800 });
      await page.waitForTimeout(500);
    }
    const part = await page.evaluate(async ({ keys, from, afterLayout }) => {
      const d = window.__tracerTestDouble!;
      const heap = () => (performance as unknown as { memory?: { usedJSHeapSize: number } }).memory?.usedJSHeapSize ?? 0;
      const out: KeyRecord[] = [];
      let overlayBefore = d.predictiveEcho()!.overlay?.visible === true;
      for (const [offset, key] of keys.entries()) {
        await new Promise((resolve) => setTimeout(resolve, 60 + Math.random() * 60));
        const heapBefore = heap();
        const t0 = performance.now();
        d.injectInput(key);
        const t1 = performance.now();
        const heapAfter = heap();
        const state = d.predictiveEcho()!;
        out.push({
          index: from + offset, key, cost: state.inputCostMs[state.inputCostMs.length - 1] ?? 0, t0, t1,
          heapBefore, heapAfter, overlayBefore, afterLayout: afterLayout && offset < 3,
        });
        overlayBefore = state.overlay?.visible === true;
      }
      return out;
    }, { keys, from, afterLayout });
    records.push(...part);
  }

  const profile = profiling
    ? (await cdp.send("Profiler.stop")).profile
    : { nodes: [], startTime: 0, endTime: 0, samples: [], timeDeltas: [] };
  const longtasks = await page.evaluate(() => (window as unknown as { __longtasks: Array<[number, number]> }).__longtasks);
  expect(records).toHaveLength(keyCount);

  // Attribute slow keys.
  const reasonOf = (record: KeyRecord, previous: KeyRecord | undefined): string[] => {
    const reasons: string[] = [];
    if (record.index === 0) reasons.push("first-key");
    if (record.afterLayout) reasons.push("after-layout");
    if (!record.overlayBefore && record.key !== "\x7f") reasons.push("burst-start");
    if (record.heapAfter < record.heapBefore || (previous && record.heapBefore < previous.heapAfter)) reasons.push("gc");
    if (longtasks.some(([start, end]) => start < record.t1 + 5 && end > record.t0 - 5)) reasons.push("longtask");
    if (record.key === "\x7f") reasons.push("backspace");
    return reasons.length ? reasons : ["unexplained"];
  };
  const costs = records.map((record) => record.cost).sort((a, b) => a - b);
  const slow = records.filter((record) => record.cost > SLOW_MS);
  const reasonCounts = new Map<string, number>();
  for (const record of slow) {
    for (const reason of reasonOf(record, records[record.index - 1])) reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
  }
  const buckets = [0.5, 1, 2, 3, 5, 10, Infinity];
  const histogram = buckets.map((limit, position) => {
    const low = position === 0 ? 0 : buckets[position - 1]!;
    return `${low}-${limit === Infinity ? "inf" : limit}ms:${costs.filter((cost) => cost > low && cost <= limit || (position === 0 && cost === 0)).length}`;
  });
  const gcKeys = records.filter((record) => reasonOf(record, records[record.index - 1]).includes("gc")).length;
  console.log(`BENCH keys=${keyCount} p50=${percentile(costs, 0.5).toFixed(2)} p95=${percentile(costs, 0.95).toFixed(2)} ` +
    `p99=${percentile(costs, 0.99).toFixed(2)} max=${costs[costs.length - 1]!.toFixed(2)} slow(>${SLOW_MS}ms)=${slow.length} ` +
    `keys_with_heap_shrink=${gcKeys} longtasks=${longtasks.length}`);
  console.log(`BENCH histogram ${histogram.join(" ")}`);
  console.log(`BENCH slow-key reasons ${JSON.stringify(Object.fromEntries(reasonCounts))}`);
  for (const record of slow.slice(0, 40)) {
    console.log(`BENCH slow key #${record.index} ${JSON.stringify(record.key)} ${record.cost.toFixed(2)}ms ` +
      `reasons=${reasonOf(record, records[record.index - 1]).join(",")}`);
  }

  // Self time per function from the CPU profile, inside the slow keys' windows and inside all keys' windows.
  const nodes = new Map<number, { name: string; where: string }>();
  for (const node of profile.nodes) {
    const frame = node.callFrame;
    nodes.set(node.id, { name: frame.functionName || "(anonymous)", where: `${frame.url.split("/").pop() ?? ""}:${frame.lineNumber + 1}` });
  }
  // The profile clock is the browser's monotonic clock and the keys' clock is performance.now(); the two differ by
  // a constant that a protocol round trip only pins down to a few ms. Choose the offset (within +-25 ms) that puts
  // the most busy samples inside the keys' windows: the keys are the only work between the 60-120 ms gaps.
  const sampleTimes: number[] = [];
  let clock = profile.startTime / 1000;
  const samples = profile.samples ?? [];
  const deltas = profile.timeDeltas ?? [];
  for (const [index] of samples.entries()) {
    clock += (deltas[index] ?? 0) / 1000;
    sampleTimes.push(clock);
  }
  const busy = samples.map((id) => {
    const name = nodes.get(id)?.name ?? "";
    return name !== "(idle)" && name !== "(program)" && name !== "(garbage collector)";
  });
  const allWindows: Array<[number, number]> = records.map((record) => [record.t0, record.t1]);
  const base = profileStartedAt - profile.startTime / 1000;
  let bestOffset = base;
  let bestHits = -1;
  for (let shift = -25; shift <= 25; shift += 0.25) {
    let hits = 0;
    for (const [index, time] of sampleTimes.entries()) {
      if (busy[index] && allWindows.some(([start, end]) => time + base + shift >= start && time + base + shift <= end)) hits += 1;
    }
    if (hits > bestHits) { bestHits = hits; bestOffset = base + shift; }
  }
  const selfTime = (windows: Array<[number, number]>): Array<[string, number]> => {
    const totals = new Map<string, number>();
    for (const [index, id] of samples.entries()) {
      const pageTime = (sampleTimes[index] ?? 0) + bestOffset;
      if (!windows.some(([start, end]) => pageTime >= start && pageTime <= end)) continue;
      const node = nodes.get(id);
      if (!node) continue;
      const label = `${node.name} ${node.where}`;
      totals.set(label, (totals.get(label) ?? 0) + (deltas[index] ?? 0) / 1000);
    }
    return [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  };
  const show = (title: string, rows: Array<[string, number]>) => {
    console.log(`BENCH top self time, ${title}`);
    for (const [label, ms] of rows) console.log(`BENCH   ${ms.toFixed(2)} ms  ${label}`);
  };
  show(`slow keys (${slow.length})`, selfTime(slow.map((record) => [record.t0, record.t1])));
  show(`all keys (${records.length})`, selfTime(records.map((record) => [record.t0, record.t1])));
  if (process.env.TRACER_PREDICT_BENCH_OUT) writeFileSync(process.env.TRACER_PREDICT_BENCH_OUT, JSON.stringify(records));
});
