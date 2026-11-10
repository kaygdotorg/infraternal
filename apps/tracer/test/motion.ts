// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Waits for the page's own motion to end, so a spec measures the resting layout and not a frame on the way there, and holds
 * that motion to the owner's rule: ease-out, and no longer than {@link MOTION_MAX_MS} (#442).
 *
 * Cards, toasts and the palette open with a transform, size or opacity transition. `getBoundingClientRect()` and Playwright's
 * `boundingBox()` include a running transform, so a measurement taken on the first frame after "visible" can be off by a
 * fraction of a pixel (a palette label 0.4 px narrower, a toast card not yet as tall as the one in front of it). That is
 * the spec reading a half-finished animation, not a layout fault, and a fixed sleep would only hide it on a fast machine.
 * The bound goes the other way: an animation that takes longer than the rule allows is a finding, so it fails the spec
 * instead of being waited out.
 */
import type { Page } from "playwright/test";

/** The longest a finite animation or transition of the product may take, in milliseconds (the owner's motion rule). */
export const MOTION_MAX_MS = 300;

/**
 * Resolves once no finite animation or transition is running on the page, and fails when one of them is longer than
 * `maxMs` (default {@link MOTION_MAX_MS}; delay, duration and repeats all count). It looks after two animation frames, so a
 * transition that a style change has queued but the browser has not started yet is counted too. Endless animations (a
 * caret that blinks, a spinner) are ignored: they never settle, are not layout and are not held to the bound. A too-long
 * animation fails at the first look, without waiting for it to finish.
 */
export async function motionSettled(page: Page, maxMs: number = MOTION_MAX_MS): Promise<void> {
  const deadline = Date.now() + SETTLE_TIMEOUT_MS;
  for (;;) {
    // Each look waits two animation frames inside the page, so the loop is paced by frames and needs no sleep.
    const { running, longest } = await page.evaluate(async () => {
      await new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done())));
      const times = document.getAnimations()
        .filter((a) => a.playState === "running")
        .map((a) => Number(a.effect?.getComputedTiming().endTime ?? Number.POSITIVE_INFINITY))
        .filter((end) => Number.isFinite(end));
      return { running: times.length, longest: Math.max(0, ...times) };
    });
    if (longest > maxMs) throw new Error(`motion rule: a finite animation on the page takes ${Math.round(longest)} ms, over the ${maxMs} ms limit`);
    if (running === 0) return;
    if (Date.now() > deadline) throw new Error(`the page's finite animations did not end within ${SETTLE_TIMEOUT_MS} ms`);
  }
}

/** How long to wait for the page's finite animations to end, in milliseconds (the expect deadline). */
const SETTLE_TIMEOUT_MS = 5_000;
