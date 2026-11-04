/** Unchanged per-key prediction CPU and echo-deadline budgets, run under perf-run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { dpr, openPredictingTerminal, resizeWithInflightInput, runKeys } from "../test/predictive-backspace-fixture";

const KEY_COST_BUDGET_MS = 2;
const BS = "\x7f";

test(`mixed backspace prediction stays within the per-key budget at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  await runKeys(page, [..."hello world"], 20);
  const second = await runKeys(page, [BS, BS, BS, "x", "y", BS, BS, BS, "p", "q", "r", BS, "s", BS, BS, BS, BS, "t"], 15);
  expect(second.maxInputCostMs).toBeLessThan(KEY_COST_BUDGET_MS);
});

test(`the first predicted key stays within the per-key budget at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const costs = await page.evaluate(async () => {
    const d = window.__tracerTestDouble!;
    for (const ch of "firstkeys") {
      d.injectInput(ch);
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
    return d.predictiveEcho()!.inputCostMs;
  });
  console.log(`first-key cost ${costs[0]!.toFixed(2)} ms; rest max ${Math.max(...costs.slice(1)).toFixed(2)} ms`);
  expect(costs.length).toBe(9);
  expect(Math.max(...costs)).toBeLessThan(KEY_COST_BUDGET_MS);
});

/** The existing echo deadline is a latency guard; shared functional hosts deliberately exercise late recovery. */
test(`typing through a layout change does not reach the echo deadline at DPR ${dpr}`, async ({ page, context }) => {
  const { start, early, late, state } = await resizeWithInflightInput(page, context);
  expect(state.cursorX).toBe(start + 26);
  expect(state.reason).not.toBe("repeated-mispredictions");
  expect(state.muted).toBe(false);
  expect(Math.max(early.worst, late.worst)).toBe(0);
  expect(early.muted || late.muted).toBe(false);
});
