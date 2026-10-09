/**
 * Glass stays glass while things move (owner rules: glass never shows legible text, and the expensive look is made
 * fast, never cheapened). Mid-flight and mid-reflow the blurred surfaces still blur, at every card level that has a
 * blur, and Frosted windows blur too. The still-frame ghost audit is glass-ghost.spec.ts; this one proves that nothing
 * turns the blur off while the camera or a reflow moves.
 */
import { expect, test, type Page } from "playwright/test";

const blurred = (page: Page): Promise<{ cards: number; withBlur: number; windows: number; windowsWithBlur: number }> => page.evaluate(() => {
  const has = (e: Element): boolean => /blur\(/.test(getComputedStyle(e).backdropFilter);
  const cards = [...document.querySelectorAll(".ui-pill, .ui-overlay-surface, .ui-panel")].filter((e) => e.getBoundingClientRect().width > 0 && getComputedStyle(e).display !== "none" && getComputedStyle(e).visibility !== "hidden");
  const windows = [...document.querySelectorAll(".ui-window[data-onscreen]")];
  return { cards: cards.length, withBlur: cards.filter(has).length, windows: windows.length, windowsWithBlur: windows.filter(has).length };
});

for (const level of [2, 3, 4]) {
  test(`card level ${level}: the blur is on during a camera flight and during a close reflow`, async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=${level}&windows=4`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1500);
    const api = (fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
    await api("flyView", "console");
    await page.waitForTimeout(1500);
    // A camera flight: sampled while the camera is moving.
    await api("flyView", "settings");
    await page.waitForTimeout(120);
    expect(await page.evaluate(() => document.querySelector(".cl-viewport")!.closest("[data-clusters]") !== null)).toBe(true);
    const flight = await blurred(page);
    expect(flight.cards, "cards on screen").toBeGreaterThan(0);
    expect(flight.withBlur, `level ${level} mid-flight: every card blurs`).toBe(flight.cards);
    expect(flight.windowsWithBlur, "mid-flight: every on-screen window blurs").toBe(flight.windows);
    await page.waitForTimeout(1500);
    // A close reflow: sampled while the reflow animations play.
    await api("flyView", "console");
    await page.waitForTimeout(1500);
    await page.locator('.cl[data-view="console"] .ui-window [data-action="close"]').last().evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(330);
    const playing = await page.evaluate(() => document.getAnimations().length);
    const reflow = await blurred(page);
    expect(reflow.withBlur, `level ${level} mid-close: every card blurs`).toBe(reflow.cards);
    expect(reflow.windowsWithBlur, "mid-close: every on-screen window blurs").toBe(reflow.windows);
    console.log(`GLASS level ${level}: mid-flight ${flight.withBlur}/${flight.cards} cards, ${flight.windowsWithBlur}/${flight.windows} windows; mid-close ${reflow.withBlur}/${reflow.cards} cards, ${reflow.windowsWithBlur}/${reflow.windows} windows, ${playing} animations playing`);
  });
}
