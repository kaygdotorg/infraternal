/**
 * Frame times of the free canvas while it zooms and pans (issue #89): the owner requires a steady 60 fps.
 * Every view is populated (scene 7 has the most), the canvas lock is off, and a 2 s zoom and a 2 s pan run
 * at 1x and at 4x CPU slowdown. Frames are the page's requestAnimationFrame deltas (what the main thread
 * delivers), so a layout or style recalculation in the frame shows up as a long frame.
 * Numbers are printed (`FRAMES ...`) so a change can be compared before and after.
 */
import { expect, test, type Browser, type CDPSession, type Page } from "playwright/test";

type Stats = { n: number; p50: number; p95: number; max: number; dropped: number; cpuMs?: number };

/** CPU seconds the browser's renderer and GPU processes have used so far (`cpuMs` = what a 2 s gesture cost). Frame times move with how busy the machine is; the CPU spent moves much less. */
async function cpuSeconds(browser: Browser): Promise<number> {
  const session = await browser.newBrowserCDPSession();
  const info = (await session.send("SystemInfo.getProcessInfo" as never)) as { processInfo: Array<{ type: string; cpuTime: number }> };
  await session.detach();
  return info.processInfo.filter((p) => p.type === "renderer" || p.type === "GPU").reduce((sum, p) => sum + p.cpuTime, 0);
}

async function measure(page: Page, browser: Browser, run: () => Promise<void>): Promise<Stats> {
  const cpu0 = await cpuSeconds(browser);
  await page.evaluate(() => {
    const w = window as unknown as { __frames: number[]; __stop: boolean };
    w.__frames = []; w.__stop = false;
    let last = performance.now();
    const tick = (t: number): void => { w.__frames.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  });
  await run();
  const cpu = (await cpuSeconds(browser)) - cpu0;
  const frames = await page.evaluate(() => { const w = window as unknown as { __frames: number[]; __stop: boolean }; w.__stop = true; return w.__frames.slice(2); });
  const sorted = [...frames].sort((a, b) => a - b);
  const at = (q: number): number => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))]!;
  return { n: frames.length, p50: +at(0.5).toFixed(1), p95: +at(0.95).toFixed(1), max: +sorted[sorted.length - 1]!.toFixed(1), dropped: frames.filter((f) => f > 20).length, cpuMs: Math.round(cpu * 1000) };
}

/**
 * The gesture is driven from inside the page (one wheel event per frame, like a trackpad), so the driver's own
 * round trips to a throttled renderer do not count as frames. Zoom is a ctrl+wheel (a pinch arrives the same way).
 */
async function gesture(page: Page, kind: "zoom" | "pan"): Promise<void> {
  await page.evaluate(({ kind: k }) => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (t: number): void => {
      const phase = (t - start) / 2000;
      if (phase >= 1) { done(); return; }
      const dir = phase < 0.5 ? -1 : 1;
      target.dispatchEvent(new WheelEvent("wheel", k === "zoom"
        ? { deltaY: dir * 14, ctrlKey: true, clientX: 720, clientY: 450, bubbles: true, cancelable: true }
        : { deltaX: dir * 24, deltaY: dir * 9, clientX: 720, clientY: 450, bubbles: true, cancelable: true }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }), { kind });
  await page.waitForTimeout(200);
}

for (const rate of [1, 4]) {
  test(`frames: a 2 s zoom and a 2 s pan on the free canvas at ${rate}x CPU`, async ({ page, browser }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/?mock=1&proto=clusters&scene=7&theme=ink&bg=soft");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    if (process.env.EXTRA_CSS) await page.addStyleTag({ content: process.env.EXTRA_CSS });
    await page.waitForTimeout(800);
    await page.keyboard.press("Control+Shift+G"); // canvas lock off: free pan and zoom, in place
    await page.waitForTimeout(500);
    const cdp: CDPSession | undefined = rate > 1 ? await page.context().newCDPSession(page) : undefined;
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
    const zoom = await measure(page, browser, () => gesture(page, "zoom"));
    const pan = await measure(page, browser, () => gesture(page, "pan"));
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
    console.log(`FRAMES ${rate}x zoom ${JSON.stringify(zoom)} pan ${JSON.stringify(pan)}`);
    expect(zoom.n).toBeGreaterThan(20);
  });
}
