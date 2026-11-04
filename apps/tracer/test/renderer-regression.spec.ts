/** Checks production renderer fixtures in Chromium. */
import { expect, test } from "playwright/test";
import { terminalFixtures } from "./terminal-fixtures";

interface RendererMetrics {
  cols: number;
  rows: number;
  cellWidth: number;
  cellHeight: number;
  configuredScrollback: number;
  outputSequence: string;
  scrollbackRows: number;
  wasmMemoryBytes: number;
}

for (const fixture of terminalFixtures) {
  test(`renderer survives ${fixture.name} and paints a canary`, async ({ page }) => {
    test.setTimeout(10 * 60_000);
    const context = page.context();
    const pageErrors: string[] = [];
    let crashed = false;
    page.on("pageerror", (error) => pageErrors.push(error.message));
    let signalCrash!: () => void;
    const crashSignal = new Promise<void>((resolve) => { signalCrash = resolve; });
    page.on("crash", () => { crashed = true; signalCrash(); });

    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");

    await page.goto("/?mock=1");
    await expect(page.getByText("TEST DOUBLE")).toBeVisible();
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), {
      timeout: 30_000,
    }).toBe(true);
    const initialMetrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    expect(initialMetrics).toBeDefined();
    const insets = await page.evaluate(() => {
      const host = document.querySelector<HTMLElement>("#terminal-host");
      if (!host) throw new Error("terminal host is missing");
      const style = getComputedStyle(host);
      return {
        outsideWidth: innerWidth - host.clientWidth,
        outsideHeight: innerHeight - host.clientHeight,
        paddingWidth: Number.parseFloat(style.paddingLeft) + Number.parseFloat(style.paddingRight),
        paddingHeight: Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom),
      };
    });
    const targetViewport = {
      width: Math.ceil(initialMetrics!.cellWidth * 205 + insets.outsideWidth + insets.paddingWidth),
      height: Math.ceil(initialMetrics!.cellHeight * 56 + insets.outsideHeight + insets.paddingHeight),
    };
    await page.setViewportSize(targetViewport);
    await expect.poll(() => page.evaluate(() => {
      const metrics = window.__tracerTestDouble?.rendererMetrics();
      return metrics ? { cols: metrics.cols, rows: metrics.rows } : undefined;
    })).toEqual({ cols: 205, rows: 56 });

    const fixtureResponse = await context.request.post("/__mock/fixture", { data: { name: fixture.name } });
    expect(fixtureResponse.status(), "the fixture must match its checked-in size and SHA256").toBe(200);
    const fixtureResult = await fixtureResponse.json() as { bytes: number; sha256: string };
    expect(fixtureResult.bytes).toBe(fixture.bytes);
    expect(fixtureResult.sha256).toBe(fixture.sha256);

    const waitForFixturePaint = async (): Promise<RendererMetrics | undefined> => {
      const deadline = Date.now() + 5 * 60_000;
      while (Date.now() < deadline) {
        const result = await Promise.race([
          page.evaluate(() => window.__tracerTestDouble?.rendererMetrics())
            .then((metrics) => ({ metrics }), () => ({ crashed: true as const })),
          crashSignal.then(() => ({ crashed: true as const })),
        ]);
        if ("crashed" in result) return undefined;
        if (result.metrics && BigInt(result.metrics.outputSequence) >= BigInt(fixture.bytes)) {
          await page.waitForTimeout(150);
          const stateResponse = await context.request.get("/__mock/state");
          const state = await stateResponse.json() as { output_sequence: string };
          const stableMetrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
          if (stableMetrics && BigInt(stableMetrics.outputSequence) >= BigInt(state.output_sequence)) return stableMetrics;
        }
        const crashObserved = await Promise.race([
          page.waitForTimeout(250).then(() => false),
          crashSignal.then(() => true),
        ]);
        if (crashObserved) return undefined;
      }
      return undefined;
    };
    const fixtureMetrics = await waitForFixturePaint();
    expect(fixtureMetrics, "the complete fixture must reach a painted output callback").toBeDefined();
    console.log(`${fixture.name} before canary: grid=${fixtureMetrics?.cols}x${fixtureMetrics?.rows}, configuredScrollback=${fixtureMetrics?.configuredScrollback}, retainedRows=${fixtureMetrics?.scrollbackRows}, wasm=${fixtureMetrics?.wasmMemoryBytes} B`);
    if (fixture.name === "behemoth.txt") {
      const graphemes = await page.evaluate(() => window.__tracerTestDouble?.graphemeText() ?? "");
      for (const cluster of ["👩🏽‍💻", "👨‍👩‍👧‍👦", "🧑🏾‍🚀", "🇩🇪", "🇺🇳"]) {
        expect(graphemes, `raw behemoth output retains ${cluster}`).toContain(cluster);
      }
      console.log("behemoth raw stream: all five Unicode clusters remain in Ghostty's grapheme buffer");
    }

    const waitForCanaryDelivery = async (): Promise<boolean> => {
      const deadline = Date.now() + 5 * 60_000;
      while (Date.now() < deadline) {
        const response = await Promise.race([
          context.request.post("/__mock/canary").then((result) => ({ status: result.status() })),
          crashSignal.then(() => ({ crashed: true as const })),
        ]);
        if ("crashed" in response) return false;
        if (response.status === 200) return true;
        expect(response.status, "the mock must append the canary only after sending the fixture").toBe(409);
        const crashObserved = await Promise.race([
          page.waitForTimeout(250).then(() => false),
          crashSignal.then(() => true),
        ]);
        if (crashObserved) return false;
      }
      return false;
    };
    const waitForCanaryPaint = async (): Promise<boolean> => {
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline) {
        const result = await Promise.race([
          page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")
            .then((screenText) => ({ screenText }), () => ({ crashed: true as const })),
          crashSignal.then(() => ({ crashed: true as const })),
        ]);
        if ("crashed" in result) return false;
        if (result.screenText.includes("__TRACER_CANARY__")) return true;
        const crashObserved = await Promise.race([
          page.waitForTimeout(250).then(() => false),
          crashSignal.then(() => true),
        ]);
        if (crashObserved) return false;
      }
      return false;
    };
    const canaryDelivered = await waitForCanaryDelivery();
    expect(canaryDelivered, "Chromium must stay alive until the fixture has been sent").toBe(true);
    const canaryPainted = await waitForCanaryPaint();
    expect(canaryPainted, "the terminal must paint the canary after the fixture").toBe(true);
    const rendererMetrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    expect(BigInt(rendererMetrics?.outputSequence ?? "0")).toBeGreaterThanOrEqual(BigInt(fixture.bytes));
    console.log(`${fixture.name}: grid=${rendererMetrics?.cols}x${rendererMetrics?.rows}, scrollback=${rendererMetrics?.scrollbackRows}, wasm=${rendererMetrics?.wasmMemoryBytes} B`);

    expect(crashed, "Chromium must keep the production page alive").toBe(false);
    expect(pageErrors, "the renderer must not report uncaught page errors").toEqual([]);
  });
}
