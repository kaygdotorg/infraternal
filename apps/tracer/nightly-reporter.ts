/**
 * A Playwright reporter for the nightly browser suite (D373, #443): it appends one JSON line per finished test to the
 * file named by `NIGHTLY_JSONL`, as the test ends.
 *
 * Playwright's own JSON reporter writes its report only when the run ends, so a suite that is stopped by its time budget
 * leaves nothing behind. These lines are on disk the moment each test finishes, so the nightly report can still file the
 * tests that failed before the stop. Without `NIGHTLY_JSONL` it does nothing, so it is safe in any other run.
 *
 * Lines: `{"kind":"begin","total":N}` once, then `{"kind":"test","file","title","status","outcome","ms","error"}` per test.
 * `file` is relative to the test folder, like the JSON reporter's `spec.file`; `outcome` is Playwright's verdict
 * (`expected`, `unexpected`, `flaky` or `skipped`). The nightly treats these lines as untrusted data when it reads them.
 */
import { appendFileSync, writeFileSync } from "node:fs";
import { relative } from "node:path";
import type { FullConfig, Reporter, Suite, TestCase, TestResult } from "playwright/test/reporter";

/** Where the lines go, or `undefined` when this reporter is not wanted. */
const target = process.env["NIGHTLY_JSONL"];
/** Longest error text kept per test; the nightly cuts it again. */
const maxError = 3000;

export default class NightlyJsonl implements Reporter {
  private root = "";

  /** Starts the file and records how many tests were planned, so a partial run can say "M of K". */
  onBegin(config: FullConfig, suite: Suite): void {
    this.root = config.rootDir;
    if (target !== undefined) writeFileSync(target, `${JSON.stringify({ kind: "begin", total: suite.allTests().length })}\n`);
  }

  /** Appends one line for a finished test (after its last attempt: the suite runs without retries). */
  onTestEnd(test: TestCase, result: TestResult): void {
    if (target === undefined) return;
    const message = result.errors.map((error) => error.message ?? "").join("\n").slice(0, maxError);
    appendFileSync(
      target,
      `${JSON.stringify({
        kind: "test",
        file: relative(this.root, test.location.file),
        title: test.title,
        status: result.status,
        outcome: test.outcome(),
        ms: result.duration,
        error: message,
      })}\n`,
    );
  }
}
