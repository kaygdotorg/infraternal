/** Checks that an active synchronized-output hold leaves the terminal input path live. */
import { expect, test } from "playwright/test";

type MockState = { accepted_input_bytes: number; output_sequence: string };

/** A dropped pooled proxy socket must not turn a state poll into a terminal assertion. */
const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());

async function mockState(page: import("playwright/test").Page): Promise<MockState> {
  return (await (await retry(() => page.request.get("/__mock/state"))).json()) as MockState;
}

test("terminal input reaches the host during an unreleased synchronized-output hold", async ({ page }) => {
  test.setTimeout(20_000);
  const request = page.context().request;
  expect((await retry(() => request.post("/__mock/reset"))).ok()).toBe(true);
  expect((await retry(() => request.post("/__mock/open-terminal"))).ok()).toBe(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await mockState(page)).accepted_input_bytes).toBe(0);

  const baseline = await retry(() => request.post("/__mock/text-output", { data: { text: "BASELINE" } }));
  expect(baseline.ok()).toBe(true);
  await expect.poll(async () => BigInt(await page.evaluate(
    () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
  ))).toBeGreaterThanOrEqual(BigInt((await baseline.json() as { bytes: number }).bytes));
  await page.locator("#terminal-host").click();
  await page.keyboard.press("c");
  await expect.poll(async () => (await mockState(page)).accepted_input_bytes).toBe(1);
  await expect.poll(async () => BigInt((await mockState(page)).output_sequence)).toBeGreaterThan(8n);

  const held = await retry(() => request.post("/__mock/live-query-output", {
    data: { text: "\u001b[?2026h\u001b[2J\u001b[HHELD" },
  }));
  expect(held.ok()).toBe(true);
  const heldSequence = (await held.json() as { output_sequence: string }).output_sequence;
  await expect.poll(async () => page.evaluate(
    () => window.__tracerTestDouble?.rendererMetrics()?.receivedSequence ?? "0",
  )).toBe(heldSequence);
  await expect.poll(() => page.evaluate(
    () => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false,
  )).toBe(true);
  expect((await retry(() => request.post("/__mock/echo-mode", { data: { mode: "normal" } }))).ok()).toBe(true);

  await page.keyboard.press("z");
  await expect.poll(async () => ({
    accepted: (await mockState(page)).accepted_input_bytes,
    held: await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false),
  }), { timeout: 1_000, intervals: [2] }).toEqual({ accepted: 2, held: true });
});
