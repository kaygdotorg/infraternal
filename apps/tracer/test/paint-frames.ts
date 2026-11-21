/**
 * Paint-frame recorder shared by the paint-alignment probe (`perf/paint-align.spec.ts`) and the second-burst D375 row
 * (`test/second-burst.spec.ts`) [#569, D375]: which animation frame shows a byte that has just arrived.
 *
 * A script injected before the app starts records, in the page itself, every animation frame (the first callback of each
 * frame, so its time is the frame start), every websocket message arrival (a capture-phase listener runs before the app's
 * own), and every canvas `fillText` with its text, canvas kind and whether it ran inside an animation-frame callback.
 * A draw made inside a frame callback is shown by that frame; a draw made in a task is shown by the next frame. "Extra
 * frames" is the frame that shows a byte minus the first frame that could: 0 is the best any code can do. Frame counts
 * do not depend on the display rate, so they are valid at 60 Hz and unthrottled alike.
 */
import { expect, type Page } from "playwright/test";

/** What the in-page recorder collects; see the file comment. */
export interface Recording {
  frames: number[];
  msgs: { t: number; created: number; id?: number }[];
  draws: { t: number; text: string; overlay: boolean; inRaf: boolean }[];
  keys: { t: number; key: string }[];
  longFrames: { start: number; duration: number; blocking: number }[];
}

export const RECORDER = `(() => {
  const pa = { frames: [], msgs: [], draws: [], keys: [], longFrames: [], inRaf: false };
  window.__pa = pa;
  const channel = new MessageChannel();
  channel.port1.onmessage = () => { pa.inRaf = false; };
  const tick = () => {
    pa.frames.push(performance.now());
    pa.inRaf = true;
    channel.port2.postMessage(0);
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  const Native = window.WebSocket;
  window.WebSocket = class extends Native {
    constructor(...args) {
      super(...args);
      this.addEventListener("message", (event) => {
        const t = performance.now();
        let id;
        if (event.data instanceof ArrayBuffer) {
          const bytes = new Uint8Array(event.data);
          for (let i = 0; i + 8 <= bytes.length; i += 1) {
            if (bytes[i] === 64 && bytes[i + 1] === 64 && bytes[i + 6] === 64 && bytes[i + 7] === 64) {
              id = Number(String.fromCharCode(bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]));
              break;
            }
          }
        }
        pa.msgs.push({ t, created: event.timeStamp, id });
      }, { capture: true });
    }
  };
  const fill = CanvasRenderingContext2D.prototype.fillText;
  CanvasRenderingContext2D.prototype.fillText = function (text, ...rest) {
    pa.draws.push({ t: performance.now(), text: String(text), overlay: this.canvas.className === "terminal-text-overlay", inRaf: pa.inRaf });
    return fill.call(this, text, ...rest);
  };
  addEventListener("keydown", (event) => { pa.keys.push({ t: performance.now(), key: event.key }); }, { capture: true });
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) pa.longFrames.push({ start: e.startTime, duration: e.duration, blocking: e.blockingDuration });
    }).observe({ type: "long-animation-frame", buffered: true });
  } catch {}
})();`;

/** Sorted-sample percentile, nearest rank. */
export function pct(values: number[], p: number): number {
  if (values.length === 0) return Number.NaN;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)]!;
}

/** The index of the first frame that starts after `t`, or -1. */
export function firstFrameAfter(frames: number[], t: number): number {
  let low = 0;
  let high = frames.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (frames[mid]! > t) high = mid; else low = mid + 1;
  }
  return low < frames.length ? low : -1;
}

/** The frame that shows a draw: its own frame when made inside a frame callback, the next one otherwise. */
export function presentingFrame(frames: number[], draw: { t: number; inRaf: boolean }): number {
  const next = firstFrameAfter(frames, draw.t);
  if (!draw.inRaf) return next;
  return next === -1 ? frames.length - 1 : next - 1;
}

/** Signs in through the test double's passkey ceremony and opens the terminal with prediction on. */
export async function signIn(page: Page, predict: boolean): Promise<void> {
  const context = page.context();
  await context.request.post("/__mock/reset");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  await page.goto("/?mock=1");
  await page.setViewportSize({ width: 1280, height: 720 });
  const setup = await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string };
  await page.locator("#setup-token").fill(setup.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("tracer_browser_test");
  await page.locator("#setup-display-name").fill("Tracer browser test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await page.goto(predict ? "/?mock=1&predict=1" : "/?mock=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorVisible ?? false)).toBe(true);
}

export async function recording(page: Page): Promise<Recording> {
  return page.evaluate(() => (window as unknown as { __pa: Recording }).__pa);
}

