/**
 * The right swipe that opens a session beside is one continuous motion (#242, owner 2026-11-01, TASTE "A swipe that creates
 * is continuous"): the row is under the finger from the first frame (no jump when the drag is recognised), moves only with
 * the finger, and after the release it settles back without ever being thrown off the screen and snapped back, and without
 * crossing to the other side (which would flash the End button). Frame times are logged for the review.
 *
 * Real touch events go through the DevTools protocol on a phone-sized page; the row's position is read on every animation
 * frame and compared with the finger's, read from the events the page really receives.
 */
import { expect, test, type Page } from "playwright/test";

const ID = "s:build-01/deploy";
const NEIGHBOUR = "s:build-01/journal";
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=none";

const open = async (page: Page, width = 1440, height = 900): Promise<void> => {
  await page.setViewportSize({ width, height });
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator(`#tree [data-id="${ID}"]`)).toBeVisible();
  await page.waitForTimeout(700);
};
const leaf = (page: Page, id = ID) => page.locator(`#tree [data-id="${id}"]`);
/** Each row's layout box (offsets, which no transform can fake): the row and its neighbour must not move or change size. */
const boxes = (page: Page, ids: string[]) => page.evaluate((list) => list.map((id) => {
  const r = document.querySelector(`#tree [data-id="${id}"]`)!.closest(".bm-row") as HTMLElement;
  return [r.offsetLeft, r.offsetTop, r.offsetWidth, r.offsetHeight];
}), ids);

/** A touch drag: real touch events through CDP at roughly 120 Hz, sampling the row on every animation frame. */
async function dragAndSample(page: Page, id: string, dx: number, opts: { steps?: number; stepMs?: number } = {}): Promise<{ frames: { t: number; x: number; finger: number; up: boolean }[]; dts: number[]; boxesAfter: number[][]; before: number[][] }> {
  const steps = opts.steps ?? 24, stepMs = opts.stepMs ?? 8;
  const box = (await leaf(page, id).boundingBox())!;
  const y = box.y + box.height / 2, x0 = box.x + 40;
  const cdp = await page.context().newCDPSession(page);
  const before = await boxes(page, [id, NEIGHBOUR]);
  await page.evaluate((sel) => {
    const el = document.querySelector(sel) as HTMLElement;
    const w = window as unknown as { __frames: { t: number; x: number; finger: number; up: boolean }[]; __stop: boolean; __finger: number; __up: boolean };
    w.__frames = []; w.__stop = false; w.__finger = 0; w.__up = false;
    // The finger is read from the events the page really receives, so the comparison with the row is frame for frame.
    const origin = el.getBoundingClientRect().left + 40;
    window.addEventListener("pointermove", (e) => { w.__finger = e.clientX - origin; }, { capture: true, passive: true });
    window.addEventListener("pointerup", () => { w.__up = true; }, { capture: true, passive: true });
    const read = (): number => { const m = new DOMMatrix(getComputedStyle(el).transform); return m.m41; };
    const loop = (t: number): void => { w.__frames.push({ t, x: read(), finger: w.__finger, up: w.__up }); if (!w.__stop) requestAnimationFrame(loop); };
    requestAnimationFrame(loop);
  }, `#tree [data-id="${id}"]`);
  const touch = async (type: "touchStart" | "touchMove" | "touchEnd", x: number): Promise<void> => {
    await cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y }] });
  };
  await touch("touchStart", x0);
  for (let i = 1; i <= steps; i += 1) { await touch("touchMove", x0 + (dx * i) / steps); await page.waitForTimeout(stepMs); }
  await touch("touchEnd", x0 + dx);
  await page.waitForTimeout(1200);
  const out = await page.evaluate(() => { const w = window as unknown as { __frames: { t: number; x: number; finger: number; up: boolean }[]; __stop: boolean }; w.__stop = true; return w.__frames; });
  const dts = out.slice(1).map((f, i) => f.t - out[i]!.t);
  return { frames: out, dts, boxesAfter: await boxes(page, [id, NEIGHBOUR]), before };
}

test.describe("the right swipe is continuous", () => {
  test.use({ hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

  test("the row is under the finger, never ahead of it, never snaps back, and its box and neighbours do not move", async ({ page }, info) => {
    await open(page, 393, 852);
    const { frames, dts, boxesAfter, before } = await dragAndSample(page, ID, 210);
    const xs = frames.map((f) => f.x);
    // 1. During the drag the row follows the finger: once the few pixels of slop are caught up (about 100 ms) it is under it, and
    //    it is never ahead of it.
    const drag = frames.filter((f) => f.finger > 0 && !f.up);
    expect(drag.length).toBeGreaterThan(10);
    for (const f of drag) expect(f.x).toBeLessThanOrEqual(f.finger + 1.5);
    for (const f of drag.filter((f) => f.finger > 90)) expect(Math.abs(f.x - f.finger)).toBeLessThan(4);
    // 2. No jump when the drag is recognised: the first frame the row moves, it is within one finger step plus the catch-up of the slop.
    const first = frames.find((f) => Math.abs(f.x) > 0.5)!;
    expect(Math.abs(first.x)).toBeLessThan(16);
    const during = xs.slice(0, frames.findIndex((f) => f.up));
    const maxStep = Math.max(...during.slice(1).map((x, i) => Math.abs(x - during[i]!)));
    expect(maxStep).toBeLessThan(18);
    // 3. After the release the row never leaves the screen to the right (it used to be thrown to the edge) and ends at rest.
    expect(Math.max(...xs)).toBeLessThan(393);
    expect(Math.abs(xs.at(-1)!)).toBeLessThan(0.5);
    // ... and never crosses to the other side while it settles: that would flash the End button for a few frames.
    expect(Math.min(...xs)).toBeGreaterThanOrEqual(-0.01);
    // 4. It never jumps back: once the finger is up, no frame moves the row left by more than the spring's own step.
    const after = xs.slice(frames.findIndex((f) => f.up));
    for (let i = 1; i < after.length; i += 1) expect(after[i]! - after[i - 1]!).toBeGreaterThan(-90);
    // 5. The row's box and its neighbour never change.
    expect(boxesAfter).toEqual(before);
    const sorted = [...dts].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)]!;
    info.annotations.push({ type: "frame-times", description: `frames ${dts.length}, p50 ${sorted[Math.floor(sorted.length / 2)]!.toFixed(1)} ms, p95 ${p95.toFixed(1)} ms, max ${sorted.at(-1)!.toFixed(1)} ms, largest row step ${maxStep.toFixed(1)} px` });
    console.log(`right swipe: frames ${dts.length}, p50 ${sorted[Math.floor(sorted.length / 2)]!.toFixed(1)} ms, p95 ${p95.toFixed(1)} ms, max ${sorted.at(-1)!.toFixed(1)} ms, largest row step ${maxStep.toFixed(1)} px`);
  });

  test("a short right swipe reveals Open beside and springs open from the finger's speed", async ({ page }) => {
    await open(page, 393, 852);
    const { frames } = await dragAndSample(page, ID, 70);
    expect(frames.at(-1)!.x).toBeGreaterThan(30);
    await expect(page.locator(`.bm-row:has([data-id="${ID}"])[data-swiped='right']`)).toHaveCount(1);
  });
});
