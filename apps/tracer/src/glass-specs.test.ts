/**
 * The D365 glass specs must never skip (#448).
 *
 * The pixel specs once opened a mockup scene and skipped themselves when it was missing, so on a branch without the mockup the
 * contrast rule was ungated and the run was still green. They now open only what the product ships. This test keeps it so: a
 * `glass-*.spec.ts` file that calls `test.skip`, `test.fixme`, `test.fail` or tests for a scene file before running fails the unit suite.
 */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** The browser specs directory. */
const DIR = join(import.meta.dir, "..", "test");

test("no glass spec can skip itself", () => {
  const specs = readdirSync(DIR).filter((f) => /^glass-.*\.spec\.ts$/.test(f));
  expect(specs.length).toBeGreaterThan(5);
  const offenders = specs.filter((f) => /\btest\.(skip|fixme|fail)\(|\bexistsSync\(|appwin-scenes|appmock=/.test(readFileSync(join(DIR, f), "utf8")));
  expect(offenders).toEqual([]);
});
