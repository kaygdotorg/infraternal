/**
 * A split from the keyboard never animates and never floods (TASTE, #141). One press is one split and lands at once:
 * no animation layer, no flip, the new window active. Holding the key for 2 s (auto-repeat) adds nothing more and
 * keeps every frame short. The pointer path keeps its animation: the new window fades in over 150 ms (#484; the droplet layer it used to play is gone). The Mac chords
 * are covered in clusters-window-actions.spec.ts (D212).
 */
import { expect, test, type Page } from "playwright/test";

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}
const count = (page: Page): Promise<number> => page.evaluate(() => document.querySelectorAll('.cl[data-view="console"] .ui-window').length);

test("a key press splits at once, and holding it splits once with short frames", { tag: "@perf" }, async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  await page.evaluate(() => {
    const w = window as unknown as { __gooSeen: number; __gaps: number[]; __at: number[]; __t0: number };
    w.__gooSeen = 0; w.__gaps = []; w.__at = [];
    new MutationObserver(() => { if (document.querySelector(".cl-goo, [data-goo]")) w.__gooSeen++; }).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-goo"] });
    let last = performance.now();
    const tick = (now: number): void => { w.__gaps.push(now - last); w.__at.push(now); last = now; requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  });
  // One and a half seconds of the same page with no key held: the frame gaps it shows on this machine right now are the noise the held key
  // is compared with. A shared build host (the nightly runs two shards beside other jobs) drops frames on its own, so a fixed count is not a fair bound.
  // sleep: sample the idle frame gaps
  await page.waitForTimeout(1500);
  const idle = await page.evaluate(() => {
    const w = window as unknown as { __gaps: number[] };
    return { late: w.__gaps.filter((g) => g > 25).length, max: Math.max(0, ...w.__gaps), ms: w.__gaps.reduce((a, b) => a + b, 0) };
  });
  const before = await count(page);
  // Split right is Ctrl+Shift+D here (Linux); on a Mac it is Command+D (D212).
  await page.keyboard.down("Control"); await page.keyboard.down("Shift");
  await page.evaluate(() => { (window as unknown as { __t0: number }).__t0 = performance.now(); });
  await page.keyboard.down("KeyD");
  // The very next frame already has the new window, active, with no silhouette.
  const at = await page.evaluate(() => new Promise<{ windows: number; active: string | null }>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r({ windows: document.querySelectorAll('.cl[data-view="console"] .ui-window').length, active: document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window[data-active]')?.dataset.windowId ?? null })))));
  expect(at.windows).toBe(before + 1);
  for (let i = 0; i < 60; i++) { await page.keyboard.down("KeyD"); await page.waitForTimeout(33); } // auto-repeat for 2 s
  await page.keyboard.up("KeyD"); await page.keyboard.up("Shift"); await page.keyboard.up("Control");
  await page.waitForTimeout(300);
  expect(await count(page), "one split per press, however long it is held").toBe(before + 1);
  const m = await page.evaluate(() => {
    const w = window as unknown as { __gooSeen: number; __gaps: number[]; __at: number[]; __t0: number };
    // The split builds one window, so a long frame or two right after the press is its own cost; none may follow.
    const late = w.__gaps.filter((g, i) => g > 25 && w.__at[i]! - w.__t0 > 800);
    return { goo: w.__gooSeen, max: Math.max(...w.__gaps), late, windowMs: w.__at[w.__at.length - 1]! - (w.__t0 + 800) };
  });
  // What the idle page dropped in the same length of time, scaled to the window the held key was measured over.
  const idleShare = idle.ms > 0 ? Math.ceil((idle.late * m.windowMs) / idle.ms) : 0;
  console.log("keyboard split: silhouette seen", m.goo, "max rAF gap", m.max.toFixed(1), "ms, long frames after the first 0.8 s", JSON.stringify(m.late), "idle late frames", idle.late, "in", idle.ms.toFixed(0), "ms, idle share", idleShare);
  expect(m.goo, "a key split plays no silhouette").toBe(0);
  // An unbound key held the same way drops a frame or two on this headless setup as well; a flood would be dozens. Allowed: what the idle page
  // dropped in the same time, plus a stray few.
  expect(m.late.length, "holding the key adds no work: at most the idle page's own dropped frames and a stray few after the split itself").toBeLessThanOrEqual(idleShare + 4);
  expect(Math.max(0, ...m.late), "and none of them is long").toBeLessThan(Math.max(60, idle.max * 1.5));
});

test("a pointer split still animates: the new window fades in over 150 ms", async ({ page }) => {
  await boot(page);
  // An opacity-only animation of the declared 150 ms, seen the moment it starts (the same probe clusters.spec.ts uses for the split fade).
  const seen = page.evaluate(() => new Promise<number | null>((r) => {
    const mo = new MutationObserver(() => {
      for (const a of document.getAnimations()) {
        const keys = (a.effect as KeyframeEffect | null)?.getKeyframes() ?? [];
        // Other pop-ups fade with their own durations (the 180 ms token); the split's is the declared 150 ms.
        if (keys.length === 2 && "opacity" in keys[0]! && a.effect!.getTiming().duration === 150) { mo.disconnect(); r(150); return; }
      }
    });
    mo.observe(document.body, { subtree: true, childList: true, attributes: true });
    setTimeout(() => r(null), 3000); // sleep: give up if no fade ever starts
  }));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:down", source: "pointer" } })));
  expect(await seen).toBe(150);
});
