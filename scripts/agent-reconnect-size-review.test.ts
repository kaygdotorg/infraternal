/** Compares the production reconnect binaries against the review's incremental size allowance [205,243], #225. */
import { expect, test } from "bun:test";
import { statSync } from "node:fs";

const baseline = process.env.INFRATERNAL_RECONNECT_SIZE_BASELINE;
const candidate = process.env.INFRATERNAL_RECONNECT_SIZE_CANDIDATE;

// Both artifacts must use the identical stripped static release recipe. This
// incremental check separates this change from pre-existing absolute ceiling debt.
test.skipIf(!baseline || !candidate)("reconnect growth stays within its 16 KiB allowance", () => {
  const before = statSync(baseline!).size;
  const after = statSync(candidate!).size;
  const growth = after - before;
  console.log(`baseline_bytes=${before} candidate_bytes=${after} growth_bytes=${growth} allowance_bytes=16384`);
  expect(growth).toBeLessThanOrEqual(16 * 1024);
});
