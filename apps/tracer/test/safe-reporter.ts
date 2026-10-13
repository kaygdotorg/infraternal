/** Report functional browser outcomes without copying request headers or authentication values into job logs. */
import type { Reporter, TestCase, TestResult, FullResult } from "playwright/types/testReporter";

export default class SafeReporter implements Reporter {
  onStdOut(chunk: string | Buffer): void { process.stdout.write(chunk); }
  onTestEnd(test: TestCase, result: TestResult): void {
    console.log(`${result.status.toUpperCase()} ${test.titlePath().join(" > ")}`);
    // Request failures include entire headers below the first line. Locations identify
    // the oracle; full network/error dumps and automatic auth-page captures are not evidence.
    for (const error of result.errors) {
      console.log(error.message?.split("\n")[0] ?? "test failed");
      if (error.location) console.log(`${error.location.file}:${error.location.line}`);
    }
  }
  onEnd(result: FullResult): void { console.log(`BROWSER ${result.status.toUpperCase()}`); }
}
