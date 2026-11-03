/** Input remains live during a synchronized-output hold; speed budgets run on the perf VM (#314). */
import { test } from "playwright/test";
import { synchronizedInputScenario } from "./synchronized-output-input-fixture";

test("terminal input reaches the host during an unreleased synchronized-output hold", async ({ page }) => {
  await synchronizedInputScenario(page);
});
