/**
 * A keyboard split lands the new window fully on screen, to the right of (or below) the one it came from, active, with
 * the camera at rest exactly where the animated split ends (#141). Exercised at 54 windows in one tiled view, from the
 * first, a middle and the last column.
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
  await page.waitForTimeout(300);
}
const SEL = '.cl[data-view="console"] .ui-window';
interface Snap { n: number; active: string | null; activeRect: { l: number; r: number; t: number; b: number } | null; vw: number; vh: number }
const snap = (page: Page): Promise<Snap> => page.evaluate((sel) => {
  const wins = [...document.querySelectorAll<HTMLElement>(sel)];
  const a = document.querySelector<HTMLElement>(`${sel}[data-active]`);
  const r = a?.getBoundingClientRect();
  return { n: wins.length, active: a?.dataset.windowId ?? null, activeRect: r ? { l: r.left, r: r.right, t: r.top, b: r.bottom } : null, vw: innerWidth, vh: innerHeight };
}, SEL);
const rectOf = (page: Page, id: string) => page.evaluate(([sel, id]) => { const r = document.querySelector<HTMLElement>(`${sel}[data-window-id="${id}"]`)!.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; }, [SEL, id] as const);
const activate = (page: Page, index: number) => page.evaluate(([sel, i]) => {
  const w = [...document.querySelectorAll<HTMLElement>(sel)][i]!;
  w.querySelector<HTMLElement>(".ui-window-body")!.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true }));
}, [SEL, index] as const);

type Probe = { setCamera(cx: number, cy: number, z: number): void; camera(): { cx: number; cy: number; z: number; tx: number; ty: number } };
/** Brings window `index` on screen (the camera is moved straight to it) and clicks its body, so it is the active one. */
async function select(page: Page, index: number): Promise<void> {
  const at = await page.evaluate(([sel, i]) => {
    const p = (window as unknown as { __tracerClusters: Probe }).__tracerClusters;
    const c = p.camera();
    const r = [...document.querySelectorAll<HTMLElement>(sel)][i]!.getBoundingClientRect();
    // world centre of the window (the viewport starts at the page's top left)
    const wx = (r.left + r.width / 2 - c.tx) / c.z, wy = (r.top + r.height / 2 - c.ty) / c.z;
    p.setCamera(wx, wy, c.z);
    return null;
  }, [SEL, index] as const);
  void at;
  await page.waitForTimeout(60);
  const box = await page.evaluate(([sel, i]) => { const r = [...document.querySelectorAll<HTMLElement>(sel)][i]!.querySelector<HTMLElement>(".ui-window-body")!.getBoundingClientRect(); return { x: r.left + 30, y: r.top + 40 }; }, [SEL, index] as const);
  await page.mouse.click(box.x, box.y);
  await page.waitForTimeout(500);
}

test("keyboard splits at 54 windows land fully on screen, beside or below the old window, which stays in view", async ({ page }) => {
  test.setTimeout(400_000);
  await boot(page);
  const RIGHT = "Control+Shift+KeyD", DOWN = "Control+Alt+Shift+KeyD";
  // Fill with full-size columns (new window right): a split right would halve the same window again and again (D212).
  while ((await snap(page)).n < 54) { await page.keyboard.press("Control+Alt+KeyR"); await page.waitForTimeout(30); }
  await page.waitForTimeout(1000);
  const problems: string[] = [];
  for (const where of ["first", "middle", "last"] as const) {
    for (const dir of ["right", "down"] as const) {
      const n = (await snap(page)).n;
      const pick = where === "first" ? 0 : where === "middle" ? Math.floor(n / 2) : n - 1;
      await select(page, pick);
      const before = await snap(page);
      const tag = `${where}/${dir}`;
      if (before.active !== (await page.evaluate(([sel, i]) => [...document.querySelectorAll<HTMLElement>(sel)][i]!.dataset.windowId, [SEL, pick] as const))) { problems.push(`${tag}: could not select the window`); continue; }
      await page.keyboard.press(dir === "right" ? RIGHT : DOWN);
      await page.waitForTimeout(1200);
      const after = await snap(page);
      const a = after.activeRect!;
      const old = await rectOf(page, before.active!);
      console.log(tag, JSON.stringify({ new: a, old }));
      if (after.n !== before.n + 1) problems.push(`${tag}: count`);
      if (after.active === before.active) problems.push(`${tag}: active did not change`);
      const inside = (r: { l: number; r: number; t: number; b: number }): boolean => r.l >= -1 && r.r <= after.vw + 1 && r.t >= -1 && r.b <= after.vh + 1;
      if (!inside(a)) problems.push(`${tag}: new window not inside the viewport ${JSON.stringify(a)}`);
      if (!inside(old)) problems.push(`${tag}: the old window left the screen ${JSON.stringify(old)}`);
      if (dir === "right" && !(a.l >= old.r - 1)) problems.push(`${tag}: not right of the old window`);
      if (dir === "down" && !(a.t >= old.b - 1)) problems.push(`${tag}: not below the old window`);
    }
  }
  expect(problems).toEqual([]);
});
