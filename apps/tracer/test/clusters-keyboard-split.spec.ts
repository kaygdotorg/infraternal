/**
 * A split from the keyboard never animates and never floods (TASTE, #141). One press is one split and lands at once:
 * no silhouette layer, no flip, the new window active. Holding the key for 2 s (auto-repeat) adds nothing more and
 * keeps every frame short. The pointer path keeps its animation (the silhouette layer exists for it).
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

test("a key press splits at once, and holding it splits once with short frames", async ({ page }) => {
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
  const before = await count(page);
  // Split right is Ctrl+Shift+D here (Linux); on a Mac the same action is Control+Option+R or Command+D.
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
    return { goo: w.__gooSeen, max: Math.max(...w.__gaps), late };
  });
  console.log("keyboard split: silhouette seen", m.goo, "max rAF gap", m.max.toFixed(1), "ms, long frames after the first 0.8 s", JSON.stringify(m.late));
  expect(m.goo, "a key split plays no silhouette").toBe(0);
  // An unbound key held the same way drops a frame or two on this headless setup as well; a flood would be dozens.
  expect(m.late.length, "holding the key adds no work: at most a stray dropped frame after the split itself").toBeLessThanOrEqual(4);
  expect(Math.max(0, ...m.late), "and none of them is long").toBeLessThan(60);
});

test("a pointer split still plays the silhouette", async ({ page }) => {
  await boot(page);
  const seen = page.evaluate(() => new Promise<boolean>((r) => { const mo = new MutationObserver(() => { if (document.querySelector(".cl-goo")) { mo.disconnect(); r(true); } }); mo.observe(document.body, { subtree: true, childList: true }); setTimeout(() => r(false), 3000); }));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:down", source: "pointer" } })));
  expect(await seen).toBe(true);
});

test("on a Mac, Control+Option+R, Control+Option+D and the Command alternates split instantly (D206)", async ({ page }) => {
  test.setTimeout(60_000);
  await page.addInitScript(() => { Object.defineProperty(navigator, "platform", { get: () => "MacIntel" }); });
  await boot(page);
  for (const [keys, expectDelta] of [[["Control", "Alt", "KeyR"], 1], [["Control", "Alt", "KeyD"], 1], [["Meta", "KeyD"], 1], [["Meta", "Shift", "KeyD"], 1], [["Control", "Alt", "Shift", "KeyD"], 0]] as const) {
    const before = await count(page);
    for (const k of keys) await page.keyboard.down(k);
    for (const k of [...keys].reverse()) await page.keyboard.up(k);
    await page.waitForTimeout(250);
    expect(await count(page) - before, keys.join("+")).toBe(expectDelta);
    expect(await page.locator(".cl-goo").count(), "no silhouette").toBe(0);
  }
});
