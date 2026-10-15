/**
 * Captures of the setup ring in the machine pill (#189, D255) for the TASTE review: key frames and short videos at
 * 1440x900, 393x852 and 375x667 in ink and paper, written outside the checkout through the shared evidence helper. Run on request:
 * `ADDHOST_PILL_CAPTURE=1 TRACER_TEST_PORT=4989 bun x playwright test test/addhost-pill-captures.spec.ts`.
 *
 * Key frames per size and theme: the status in the wizard, mid-flight (taken from a screencast, because a 280 ms
 * flight cannot be caught by single screenshots), the pill with 2 of 4 arcs filled, the tick, the system icon, the
 * failed arc and the failure popover. Videos (happy path) for the two main sizes.
 */
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { test, type Browser, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("addhost-pill");
const SIZES = [{ name: "1440x900", width: 1440, height: 900, touch: false }, { name: "393x852", width: 393, height: 852, touch: true }, { name: "375x667", width: 375, height: 667, touch: true }];
const THEMES = ["ink", "paper"];
const url = (theme: string, extra = ""): string => `/?mock=1&proto=clusters&scene=3&bg=none&theme=${theme}&addhost-demo=pill${extra}`;
/** The stills run the stages three times slower and hold the tick for 3 s (the videos keep the real timings) so a slow screenshot cannot miss a state. */
const STILLS = "&tickhold=3000&slow=3";

test.skip(process.env.ADDHOST_PILL_CAPTURE !== "1", "captures are produced on request");
test.describe.configure({ mode: "serial" });

const o2Pill = (page: Page) => page.locator(".ui-window-pill", { hasText: "o2" }).first();

async function context(browser: Browser, size: (typeof SIZES)[number], video: string | undefined) {
  return browser.newContext({
    viewport: { width: size.width, height: size.height }, hasTouch: size.touch, isMobile: size.touch, deviceScaleFactor: size.touch ? 3 : 2,
    baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`,
    ...(video ? { recordVideo: { dir: video, size: { width: size.width, height: size.height } } } : {}),
  });
}

for (const size of SIZES) for (const theme of THEMES) {
  test(`key frames ${size.name} ${theme}`, async ({ browser }) => {
    test.setTimeout(240_000);
    mkdirSync(OUT, { recursive: true });
    const prefix = `${OUT}/${size.name}-${theme}`;
    const withVideo = size.name !== "375x667";
    const tmp = `${OUT}/.video-${size.name}-${theme}`;
    // The video is its own run at the real timings (the tick holds 600 ms); the stills below hold the tick longer.
    if (withVideo) {
      const videoCtx = await context(browser, size, tmp);
      const videoPage = await videoCtx.newPage();
      await videoPage.goto(url(theme));
      await videoPage.waitForSelector(".ui-window .ui-setup-ring", { timeout: 60_000 });
      await videoPage.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 40_000 });
      await videoPage.waitForTimeout(1200);
      await videoCtx.close();
      const { readdirSync } = await import("node:fs");
      const file = readdirSync(tmp).find((f) => f.endsWith(".webm"));
      if (file) renameSync(`${tmp}/${file}`, `${prefix}-happy-path.webm`);
    }
    const ctx = await context(browser, size, undefined);
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    const frames: Array<{ t: number; data: string }> = [];
    cdp.on("Page.screencastFrame", (f: { metadata: { timestamp?: number }; data: string; sessionId: number }) => { frames.push({ t: (f.metadata.timestamp ?? 0) * 1000, data: f.data }); void cdp.send("Page.screencastFrameAck", { sessionId: f.sessionId }); });
    await page.addInitScript(() => { const w = window as unknown as { __flyAt?: number }; const tick = (): void => { if (w.__flyAt === undefined && document.querySelector(".ui-setup-fly")) w.__flyAt = performance.timeOrigin + performance.now(); requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
    await page.goto(url(theme, STILLS));
    await cdp.send("Page.startScreencast", { format: "png", everyNthFrame: 1 });

    // 1. The wizard's own progress, with the status that is about to move.
    await page.waitForSelector('.ah-stage-row[data-stage="install"][data-state="running"]', { timeout: 60_000 });
    await page.screenshot({ path: `${prefix}-1-wizard-status.png` });

    // 2. Mid-flight, from the screencast frame nearest the middle of the flight.
    await page.waitForSelector(".ui-window .ui-setup-ring", { timeout: 20_000 });
    await page.waitForTimeout(300);
    await cdp.send("Page.stopScreencast");
    const flyAt = await page.evaluate(() => (window as unknown as { __flyAt?: number }).__flyAt);
    if (flyAt !== undefined) {
      // Every screencast frame of the flight (up to six, evenly spread): single screenshots cannot catch 280 ms.
      const flight = frames.filter((f) => f.t >= flyAt - 40 && f.t <= flyAt + 420);
      const step = Math.max(1, Math.floor(flight.length / 6));
      flight.filter((_, i) => i % step === 0).slice(0, 6).forEach((f, i) => writeFileSync(`${prefix}-2-flight-${i + 1}.png`, Buffer.from(f.data, "base64")));
    }

    // 3-5. In the pill: 2 of 4 arcs, the tick, the system icon (the pill and its neighbourhood, taken close).
    const pill = o2Pill(page);
    const closeUp = async (name: string): Promise<void> => {
      const box = await pill.boundingBox();
      if (box) await page.screenshot({ path: `${prefix}-${name}-closeup.png`, clip: { x: Math.max(0, box.x - 10), y: box.y - 10, width: Math.min(size.width - Math.max(0, box.x - 10), box.width + 20), height: box.height + 20 } });
    };
    await page.waitForFunction((k) => document.querySelectorAll('.ui-window .ui-setup-fill[data-state="done"]').length >= k, 2, { timeout: 20_000 });
    await page.waitForTimeout(280);
    await closeUp("3-pill-2of4");
    await page.screenshot({ path: `${prefix}-3-pill-2of4.png` });
    await page.waitForSelector('.ui-window .ui-setup-ring[data-phase="tick"]', { timeout: 20_000 });
    await page.waitForTimeout(220);
    await closeUp("4-tick");
    await page.screenshot({ path: `${prefix}-4-tick.png` });
    await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 10_000 });
    await page.waitForTimeout(300);
    await closeUp("5-os-icon");
    await page.screenshot({ path: `${prefix}-5-os-icon.png` });
    await page.waitForTimeout(600);
    await ctx.close();
    // 6-7. The failure: the failed arc, then the popover the pill opens.
    const failCtx = await context(browser, size, undefined);
    const fail = await failCtx.newPage();
    await fail.goto(url(theme, "&fail=join&slow=3"));
    await fail.waitForSelector('.ui-window .ui-setup-fill[data-state="failed"]', { timeout: 60_000 });
    await fail.waitForTimeout(500);
    await fail.screenshot({ path: `${prefix}-6-failed-arc.png` });
    const box = await o2Pill(fail).boundingBox();
    if (box) await fail.screenshot({ path: `${prefix}-6-failed-arc-closeup.png`, clip: { x: Math.max(0, box.x - 10), y: box.y - 10, width: Math.min(size.width - Math.max(0, box.x - 10), box.width + 20), height: box.height + 20 } });
    if (size.touch) await o2Pill(fail).tap(); else await o2Pill(fail).click();
    await fail.waitForSelector('[role="dialog"][aria-label="Setup of o2"]');
    await fail.waitForTimeout(450);
    await fail.screenshot({ path: `${prefix}-7-failure-popover.png` });
    await failCtx.close();
  });
}
