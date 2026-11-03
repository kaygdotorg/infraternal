/** Unchanged sign-in, prediction, resume and first-paint budgets, run under perf-run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { terminalScenario } from "../test/terminal-scenario";

test("first run, passkey login, terminal resume, and the latency probe", async ({ page }, info) => {
  const metrics = await terminalScenario(page, info, { performanceSamples: true });
  expect.soft(metrics.returningSigninP99).toBeLessThanOrEqual(metrics.returningSigninBudgetMs);
  expect.soft(metrics.predictedP99).toBeLessThanOrEqual(17);
  expect.soft(metrics.resumeP99).toBeLessThanOrEqual(metrics.resumeBudgetMs);
});

/** Measure the status round trip and access paint across repeated cold documents. */
test("access screens render within the local first-paint budget", async ({ page }) => {
  test.setTimeout(120_000);
  // This is the local-paint budget. Serve assets directly, while the terminal
  // latency scenario above continues to use the configured network profile.
  const backendPort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
  const localOrigin = `http://localhost:${backendPort}`;
  const rttMs = 0;
  let renderBudgetPassed = true;
  await page.context().request.post("/__mock/reset");
  for (const setupRequired of [true, false]) {
    const samples: number[] = [];
    const firstPaints: number[] = [];
    for (let index = 0; index < 30; index += 1) {
      // Fresh surfaces avoid Chromium reusing an unchanged compositor frame on reload.
      const sample = await page.context().newPage();
      await sample.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: setupRequired } }));
      await sample.goto(localOrigin);
      await expect(sample.locator(setupRequired ? "#setup-card" : "#login-passkey")).toBeVisible();
      firstPaints.push(await sample.evaluate(() =>
        performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? performance.now()));
      // A compositor screenshot confirms painted pixels. The timestamp after capture
      // is an upper bound, including screenshot overhead, rather than FCP telemetry.
      await sample.screenshot();
      samples.push(await sample.evaluate(() => performance.now()));
      await sample.close();
    }
    samples.sort((left, right) => left - right);
    firstPaints.sort((left, right) => left - right);
    const p99 = samples[29] ?? Infinity;
    const name = setupRequired ? "setup" : "signin";
    const firstPaintP99 = firstPaints[29] ?? Infinity;
    renderBudgetPassed &&= p99 < 1000;
    console.log(
      `METRIC name=access_screen_render_upper_bound_${name} source=tracer-production-build n=${samples.length} ` +
        `configured_rtt_ms=${rttMs} p50_ms=${(samples[14] ?? Infinity).toFixed(2)} p99_ms=${p99.toFixed(2)} ` +
        `budget_ms=1000 result=${p99 < 1000 ? "PASS" : "FAIL"}`,
    );
    console.log(
      `METRIC name=access_screen_first_contentful_paint_${name} source=tracer-production-build n=${firstPaints.length} ` +
        `configured_rtt_ms=${rttMs} p50_ms=${(firstPaints[14] ?? Infinity).toFixed(2)} p99_ms=${firstPaintP99.toFixed(2)} ` +
        "budget_ms=1000 result=REPORT",
    );
  }
  expect(renderBudgetPassed).toBe(true);
});
