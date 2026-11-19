/**
 * Waits until a glass surface has stopped changing, so a pixel measurement reads one state of it and not a transition (D365, #448).
 *
 * A fixed sleep was the weak point: under load the opening animation, the glass's first sample of the picture and the colour
 * transitions that follow it can all still be running when the sleep ends. Settled here means: the surface exists, nothing on
 * or in it is animating or transitioning, and its tint, its text colours and its box are the same in two reads that are one sample
 * interval of the adaptive glass apart (it only ever writes on that cadence). The reads and the wait are what the glass does, not a guess.
 */
import type { Page } from "playwright/test";

/** The glass's sampling cadence in ms (`SAMPLE_INTERVAL_MS` in `packages/ui/src/glass-adapt.on-demand.ts`), plus a frame of margin. */
const STABLE_MS = 300;

/** What a surface looks like right now, as text: box, tint, text colours, fill and the count of running animations. */
export async function look(page: Page, selector: string): Promise<string> {
  return page.evaluate((sel) => {
    const el = document.querySelector<HTMLElement>(sel);
    if (!el) return "absent";
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    const running = el.getAnimations({ subtree: true }).filter((a) => a.playState === "running").length;
    return [Math.round(r.left * 10), Math.round(r.top * 10), Math.round(r.width * 10), Math.round(r.height * 10), s.getPropertyValue("--overlay"), s.getPropertyValue("--fg"), s.getPropertyValue("--fg-2"), s.getPropertyValue("--fg-3"), s.backgroundColor, s.color, s.opacity, el.dataset.glassUnder ?? "", running].join("|");
  }, selector);
}

/** Resolves once `selector` looks the same, with nothing animating, across {@link STABLE_MS}; throws after `timeout` ms. */
export async function settled(page: Page, selector: string, timeout = 15_000): Promise<void> {
  const until = Date.now() + timeout;
  let before = await look(page, selector);
  for (;;) {
    // sleep: the glass writes on a 250 ms cadence, so a state that holds for 300 ms is the settled one
    await page.waitForTimeout(STABLE_MS);
    const now = await look(page, selector);
    if (now === before && now !== "absent" && !/\|[1-9]\d*$/.test(now)) return;
    if (Date.now() > until) throw new Error(`${selector} did not settle in ${timeout} ms: ${before} -> ${now}`);
    before = now;
  }
}
