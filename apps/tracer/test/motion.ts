// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Waits for the page's own motion to end, so a spec measures the resting layout and not a frame on the way there.
 *
 * Cards, toasts and the palette open with a transform, size or opacity transition. `getBoundingClientRect()` and Playwright's
 * `boundingBox()` include a running transform, so a measurement taken on the first frame after "visible" can be off by a
 * fraction of a pixel (a palette label 0.4 px narrower, a toast card not yet as tall as the one in front of it). That is
 * the spec reading a half-finished animation, not a layout fault, and a fixed sleep would only hide it on a fast machine.
 */
import { expect, type Page } from "playwright/test";

/**
 * Resolves once no finite animation or transition is running on the page. It looks after two animation frames, so a
 * transition that a style change has queued but the browser has not started yet is counted too. Endless animations (a
 * caret that blinks, a spinner) are ignored: they never settle and are not layout. Polls with the expect deadline.
 */
export async function motionSettled(page: Page): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(async () => {
          await new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done())));
          return document.getAnimations().filter((a) => a.playState === "running" && Number.isFinite(a.effect?.getComputedTiming().endTime ?? Number.POSITIVE_INFINITY)).length;
        }),
      { message: "the page's finite animations and transitions end" },
    )
    .toBe(0);
}
