/** Held-output input budget (one 120 Hz frame, D375), run under perf-run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { FRAME_MS } from "../test/latency-targets";
import { synchronizedInputScenario } from "../test/synchronized-output-input-fixture";

test("terminal input is sent within one frame during an unreleased synchronized-output hold", async ({ page }) => {
  const metrics = await synchronizedInputScenario(page);
  // D375 moved frame budgets from 60 Hz (16 ms) to 120 Hz.
  expect(metrics.sendMs).toBeLessThanOrEqual(FRAME_MS);
  expect(metrics.framesAfterRelease).toBeGreaterThanOrEqual(0);
  expect(metrics.framesAfterRelease).toBeLessThanOrEqual(1);
});
