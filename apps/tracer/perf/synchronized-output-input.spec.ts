/** Unchanged 16 ms held-output input budget, run under perf-run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { synchronizedInputScenario } from "../test/synchronized-output-input-fixture";

test("terminal input is sent within 16 ms during an unreleased synchronized-output hold", async ({ page }) => {
  const metrics = await synchronizedInputScenario(page);
  expect(metrics.sendMs).toBeLessThanOrEqual(16);
  expect(metrics.framesAfterRelease).toBeGreaterThanOrEqual(0);
  expect(metrics.framesAfterRelease).toBeLessThanOrEqual(1);
});
