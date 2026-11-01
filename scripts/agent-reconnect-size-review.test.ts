/** Reports production reconnect binary growth [205,243 amended 2026-11-01], #225. */
import { expect, test } from "bun:test";
import { statSync } from "node:fs";

const baseline = process.env.INFRATERNAL_RECONNECT_SIZE_BASELINE;
const candidate = process.env.INFRATERNAL_RECONNECT_SIZE_CANDIDATE;

// Both artifacts must use the identical stripped static release recipe. This
// report attributes this change independently of the merged size baseline.
test.skipIf(!baseline || !candidate)("reconnect growth is reported without an approval cap", () => {
  const before = statSync(baseline!).size;
  const after = statSync(candidate!).size;
  const growth = after - before;
  console.log(`baseline_bytes=${before} candidate_bytes=${after} growth_bytes=${growth} (report only, D243 amended 2026-11-01)`);
  expect(before).toBeGreaterThan(0);
  expect(after).toBeGreaterThan(0);
});
