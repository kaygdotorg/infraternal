/** Shared production frame-meter fixture for functional incidents and perf-VM budgets (#314). */
import { expect, type Page } from "playwright/test";

const URL = "/?mock=1&proto=clusters&scene=7&theme=ink&bg=none";

type Hud = { bench(calls?: number, batch?: number): { meanUs: number; p99Us: number; maxUs: number }; selfTime(): { frames: number; meanMs: number }; pauseRepaint(): void; flush(): void; finish(): void; state(): { sid: string; incidents: number; refresh: number } };
export const hud = (page: Page) => ({
  call: <T,>(fn: (h: Hud) => T): Promise<T> => page.evaluate(`(${fn.toString()})(window.__perfHud)`) as Promise<T>,
});

export async function open(page: Page, query = "&fps=bench"): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(URL + query);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (query.includes("bench")) await page.waitForFunction("!!window.__perfHud", undefined, { timeout: 10_000 });
  await page.keyboard.press("Control+Shift+G"); // canvas lock off: free pan
  await page.waitForTimeout(1500);
}
