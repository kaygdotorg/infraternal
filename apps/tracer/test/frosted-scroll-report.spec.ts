/**
 * The numbers behind #256: a scripted 3 s sideways pan with 1, 4 and 12 windows, frosting off (Solid windows, the
 * baseline) and Frosted (the blur runs at rest and while the canvas pans, TASTE "Frosted means really frosted").
 * It reports; it asserts only that it ran. It is skipped unless `FROSTED_REPORT=1`, because one run takes
 * minutes. Each configuration is run `FROSTED_REPS` times (default 3) and the run with the median p95 is reported.
 *
 *   FROSTED_REPORT=1 TRACER_TEST_PORT=4256 bun x playwright test --workers=1 test/frosted-scroll-report.spec.ts
 *
 * Headless on a machine without a GPU: relative numbers only. The table is printed as Markdown, and the raw runs go
 * to `$INFRATERNAL_EVIDENCE_DIR/frosted-scroll/summary.json` (outside the checkout).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { test } from "playwright/test";
import { measure, type ScrollResult } from "./frosted-scroll-harness";
import { tracerEvidencePath } from "./evidence-path";

const reps = Number(process.env.FROSTED_REPS ?? 3);
const dpr = Number(process.env.FROSTED_DPR ?? 1) as 1 | 2;
const CONFIGS = [
  { label: "frosting off (Solid)", windows: 1 as const },
  { label: "Frosted", windows: 4 as const },
];

const median = (runs: ScrollResult[]): ScrollResult => [...runs].sort((a, b) => a.p95 - b.p95)[Math.floor(runs.length / 2)]!;
const f = (n: number): string => n.toFixed(1);

test.describe("frosted scroll report", () => {
  test.skip(process.env.FROSTED_REPORT !== "1", "set FROSTED_REPORT=1 to run the report");
  const all: Record<string, ScrollResult> = {};

  for (const count of [1, 4, 12]) {
    test(`${count} window${count === 1 ? "" : "s"}`, async ({ browser }) => {
      test.setTimeout(reps * CONFIGS.length * 60_000);
      for (const config of CONFIGS) {
        const runs: ScrollResult[] = [];
        for (let i = 0; i < reps; i++) runs.push(await measure(browser, { ...config, count, dpr }));
        const m = median(runs);
        all[`${count}|${config.label}`] = m;
        console.log(`| ${count} | ${config.label} | ${f(m.p50)} / ${f(m.p95)} / ${f(m.max)} | ${f(m.ms.paint + m.ms.layerize)} | ${f(m.ms.raster)} | ${f(m.ms.draw)} (${f(m.ms.drawPerFrame)}/frame) | ${m.layers.first}→${m.layers.max} | ${m.onscreen} | p95 of ${runs.length}: ${runs.map((r) => f(r.p95)).join(", ")} |`);
      }
      const dir = tracerEvidencePath("frosted-scroll");
      mkdirSync(dir, { recursive: true });
      writeFileSync(`${dir}/summary-${count}.json`, JSON.stringify(all, null, 1));
    });
  }
});
