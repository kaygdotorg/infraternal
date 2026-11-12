// SPDX-License-Identifier: AGPL-3.0-only
/**
 * With Reduce Motion on, the first-run page must be still in both schemes (#510 item 3).
 *
 * J509 saw the iPhone Simulator stall typing for 10+ minutes on the dark first-run page with Reduce Motion on (the light
 * page: about 2 minutes) and suspected something still animating in dark. This measures it on the real server's page,
 * walking the setup steps in each scheme with `prefers-reduced-motion: reduce`: it counts running CSS/Web animations,
 * timer and animation-frame callbacks per second, and compares two screenshots of the backdrop a second apart. A still
 * page has no running animations, no frame callbacks, and identical pixels. Numbers go to the evidence directory.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { startRealServer } from "./server";

/** What a still page reports after the steps settle, over a one-second window. */
interface Activity { animations: string[]; rafPerSecond: number; timersPerSecond: number; backdropChanged: boolean }

/** Counts callbacks and running animations for one second, and compares two backdrop screenshots. */
async function measure(page: Page): Promise<Activity> {
  await page.waitForTimeout(1500); // sleep: let the card's entrance and the backdrop's mount finish before measuring
  const first = await page.screenshot();
  const counts = await page.evaluate(() => new Promise<{ animations: string[]; raf: number; timers: number }>((resolve) => {
    const w = window as unknown as { __raf: number; __timers: number };
    const raf0 = w.__raf, timers0 = w.__timers;
    const animations = document.getAnimations().filter((a) => a.playState === "running").map((a) => `${(a as CSSAnimation).animationName ?? (a as CSSTransition).transitionProperty ?? "?"} on ${(a.effect?.target as Element | null)?.className || (a.effect?.target as Element | null)?.tagName}`);
    setTimeout(() => resolve({ animations, raf: w.__raf - raf0, timers: w.__timers - timers0 }), 1000);
  }));
  const second = await page.screenshot();
  return { animations: counts.animations, rafPerSecond: counts.raf, timersPerSecond: counts.timers, backdropChanged: !first.equals(second) };
}

for (const scheme of ["dark", "light"] as const) {
  test(`the first-run page is still under Reduce Motion in ${scheme}`, async ({ browser }) => {
    test.setTimeout(180_000);
    const server = await startRealServer({});
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 402, height: 874 }, reducedMotion: "reduce", colorScheme: scheme });
    const page = await context.newPage();
    await page.addInitScript(() => {
      const w = window as unknown as { __raf: number; __timers: number };
      w.__raf = 0; w.__timers = 0;
      const raf = window.requestAnimationFrame.bind(window);
      window.requestAnimationFrame = (cb) => raf((t) => { w.__raf++; cb(t); });
      const timeout = window.setTimeout.bind(window);
      // setTimeout counts when its callback runs; the page's own interval timers count each tick.
      (window as unknown as { setTimeout: unknown }).setTimeout = ((cb: TimerHandler, ms?: number, ...rest: unknown[]) => timeout(typeof cb === "function" ? (...a: unknown[]) => { w.__timers++; (cb as (...x: unknown[]) => void)(...a); } : cb, ms, ...rest)) as typeof window.setTimeout;
    });
    const results: Record<string, Activity> = {};
    try {
      await page.goto(server.origin);
      await page.locator("#setup-token").waitFor();
      results["token"] = await measure(page);
      await page.locator("#setup-token").evaluate((element, token) => {
        (element as HTMLInputElement).value = token;
        element.dispatchEvent(new Event("input", { bubbles: true }));
      }, server.token);
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await page.locator("#setup-username").waitFor();
      results["identity"] = await measure(page);
      const dir = tracerEvidencePath("reduced-motion-510");
      mkdirSync(dir, { recursive: true });
      writeFileSync(`${dir}/${scheme}.json`, JSON.stringify(results, null, 2));
      test.info().annotations.push({ type: "measured", description: JSON.stringify(results) });
      for (const [step, activity] of Object.entries(results)) {
        expect(activity.animations, `${scheme} ${step}: running animations`).toEqual([]);
        expect(activity.rafPerSecond, `${scheme} ${step}: animation frames per second`).toBe(0);
        expect(activity.backdropChanged, `${scheme} ${step}: the page changed between two screenshots`).toBe(false);
      }
    } finally {
      await context.close();
      await server.dispose();
    }
  });
}
