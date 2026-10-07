/** Exercises opt-in local echo directly against the production Ghostty renderer build. */
import { expect, test } from "playwright/test";

test("predictive echo draws only when Ghostty reports a visible normal-screen cursor", async ({ page }) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0))
    .toBeGreaterThan(60);

  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("$");
  const cursor = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  expect(Boolean(cursor?.cursorVisible)).toBe(true);

  await page.keyboard.press("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("a");
  await expect.poll(async () => ((await (await context.request.get("/__mock/state")).json()) as { echoed_text: string }).echoed_text)
    .toBe("a");
  await context.request.post("/__mock/drop-next-ack");
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("b"));
  await expect.poll(async () => ((await (await context.request.get("/__mock/state")).json()) as { echoed_text: string }).echoed_text)
    .toBe("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ab");

  await context.request.post("/__mock/echo-mode", { data: { mode: "none" } });
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("p"));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("p");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? false), { timeout: 3000 })
    .toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");

  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("s"));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? true))
    .toBe(false);
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("ok"));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("ok");

  const inject = (data: string) => page.evaluate((value) => window.__tracerTestDouble?.injectInput(value), data);
  const outputSequence = () => page.evaluate(() => Number(window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  const resetScreen = async (): Promise<void> => {
    const response = await context.request.post("/__mock/screen-reset");
    const state = await response.json() as { output_sequence: string };
    await expect.poll(async () => BigInt(await page.evaluate(
      () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
    ))).toBeGreaterThanOrEqual(BigInt(state.output_sequence));
  };
  const waitForOutputBytes = async (previous: number, count: number): Promise<void> => {
    await expect.poll(outputSequence).toBeGreaterThanOrEqual(previous + count);
  };
  await context.request.post("/__mock/alternate-screen", { data: { active: true } });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.reason ?? ""))
    .toBe("unsafe-screen");
  await inject("u");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await context.request.post("/__mock/alternate-screen", { data: { active: false } });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.enabled ?? false))
    .toBe(true);

  await context.request.post("/__mock/echo-mode", { data: { mode: "wrong" } });
  for (const [index, key] of ["m", "n", "o"].entries()) {
    await inject(key);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.mispredictions ?? 0))
      .toBe(index + 1);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
      .toBe("");
  }
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? false)).toBe(true);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await inject("r");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? true)).toBe(false);

  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  let previousOutput = await outputSequence();
  await inject("ABC");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABC");
  await waitForOutputBytes(previousOutput, 3);
  previousOutput = await outputSequence();
  const cursorBeforeMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  await inject("\u001b[D");
  await waitForOutputBytes(previousOutput, 3);
  const cursorAfterMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  expect(cursorAfterMove).toBe(cursorBeforeMove - 1);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: 500 } });
  await inject("Z");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("Z");
  await expect.poll(() => page.locator(".terminal-text-overlay text").textContent()).toBe("Z");
  const movedCursor = await page.evaluate(() => ({
    x: Number(document.querySelector<SVGTextElement>(".terminal-text-overlay text")?.getAttribute("x")),
    cellWidth: window.__tracerTestDouble?.rendererMetrics()?.cellWidth ?? 0,
    cursorX: window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0,
  }));
  expect(movedCursor.cursorX).toBe(cursorAfterMove);
  expect(movedCursor.x).toBeCloseTo(movedCursor.cellWidth * cursorAfterMove, 1);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("Z");
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });

  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  previousOutput = await outputSequence();
  await inject("ABCZ");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABCZ");
  await waitForOutputBytes(previousOutput, 4);
  previousOutput = await outputSequence();
  await inject("\u007f");
  await waitForOutputBytes(previousOutput, 3);
  const afterBackspace = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  expect(afterBackspace).toContain("ABC");
  expect(afterBackspace).not.toContain("ABCZ");

  previousOutput = await outputSequence();
  await inject("pasted words");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("pasted words");
  await waitForOutputBytes(previousOutput, 12);
  await inject("ok");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("ok");

  await page.setViewportSize({ width: 393, height: 852 });
  await page.evaluate(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1&theme=ink");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await inject("x");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("x");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("x");
});
