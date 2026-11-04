/**
 * Three palette annoyances the owner reported (TASTE: containers hug their content, a phone sees phone things, glass shows
 * colour and never legible text; D219). Each runs against the test double's mock canvas.
 *
 * 1. No row of the palette may render without a title, in the whole list and in the list scoped to the Settings view.
 * 2. The footer of key hints is for a keyboard: gone on touch and on narrow screens, and the list takes its room.
 * 3. Text behind the open palette is not legible through it, at the default card level, over real terminal text.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { devices, expect, test, type Page } from "playwright/test";
import { denseText, ghost } from "./ghost-metric";

const CAPTURES = tracerEvidencePath("palette-polish");
mkdirSync(CAPTURES, { recursive: true });
const URL = (theme: string): string => `/?mock=1&proto=clusters&scene=3&theme=${theme}`;
const PALETTE_KEY = "Control+Shift+K";

async function open(page: Page, theme = "ink"): Promise<void> {
  await page.goto(URL(theme));
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
}

test("no palette row renders without a title, whole list and scoped to Settings", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  await page.keyboard.press(PALETTE_KEY);
  await expect(page.locator("#palette")).toBeVisible();
  const blank = () => page.locator("#palette-results .result").evaluateAll((rows) => rows.filter((r) => !(r.querySelector(".result-label")?.textContent ?? "").trim()).map((r) => (r as HTMLElement).dataset.action));
  expect(await page.locator("#palette-results .result").count()).toBeGreaterThan(20);
  expect(await blank()).toEqual([]);
  // Every settings entry the palette offers carries its component and group ("Appearance › Theme").
  await page.keyboard.type("settings");
  const settings = await page.locator("#palette-results .result-label").allTextContents();
  expect(settings.filter((t) => t.includes(" › ")).length).toBeGreaterThanOrEqual(8);
  await page.keyboard.press("Escape");
  // The list scoped to the Settings view: its windows are named by their groups.
  await page.evaluate(() => {
    const p = (window as unknown as { __tracerClusters: { views(): Array<{ id: string; x: number; y: number }>; setCamera(x: number, y: number, z: number): void } }).__tracerClusters;
    const v = p.views().find((view) => view.id === "settings")!;
    p.setCamera(v.x + 60, v.y + 60, 0.5);
  });
  await page.waitForTimeout(700);
  await page.locator('.cl[data-view="settings"] .cl-label').hover();
  await page.locator(".cl-summary-all").click();
  await expect(page.locator("#palette")).toBeVisible();
  const names = await page.locator("#palette-results .result-label").allTextContents();
  expect(names.length).toBeGreaterThanOrEqual(5);
  expect(names).toContain("Theme");
  expect(await blank()).toEqual([]);
});

test("desktop keeps the key-hint footer", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  await page.keyboard.press(PALETTE_KEY);
  await expect(page.locator(".palette-foot")).toBeVisible();
});

for (const [w, h] of [[393, 852], [375, 667]] as const) {
  test(`touch ${w}x${h}: no key-hint footer, and the list is taller for it`, async ({ browser }) => {
    const ctx = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: w, height: h }, deviceScaleFactor: 2 });
    const page = await ctx.newPage();
    await page.goto(URL("ink"));
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(900);
    // The same D222 key phone-gutter.spec.ts uses; the layout under test does not depend on how the palette opened.
    await page.keyboard.press(PALETTE_KEY);
    await expect(page.locator("#palette")).toBeVisible();
    await expect(page.locator(".palette-foot")).toBeHidden();
    const m = await page.evaluate(() => {
      const pal = document.getElementById("palette")!.getBoundingClientRect();
      const res = document.getElementById("palette-results")!.getBoundingClientRect();
      return { palBottom: pal.bottom, resBottom: res.bottom, resHeight: res.height, vh: innerHeight };
    });
    // The list now ends at the palette's own bottom edge, and is taller than the old 54vh cap.
    expect(Math.abs(m.palBottom - m.resBottom)).toBeLessThanOrEqual(2);
    expect(m.resHeight).toBeGreaterThan(m.vh * 0.54);
    // No title is ever squeezed out by its hint: every row's label keeps room to read (the "Settings" row lost its title on a phone).
    const labels = await page.locator("#palette-results .result-label").evaluateAll((els) => els.map((el) => ({ text: el.textContent, w: el.getBoundingClientRect().width, scroll: (el as HTMLElement).scrollWidth })));
    for (const l of labels) expect(l.w, `label "${l.text}" has room`).toBeGreaterThanOrEqual(Math.min(l.scroll, 60) - 1);
    await page.screenshot({ path: resolve(CAPTURES, `touch-${w}x${h}.png`) });
    await ctx.close();
  });
}

/**
 * Glass: over dense text, on a high-density screen (where the owner saw it), at each card level that has glass, the
 * palette's own area shows none of the text behind. The surface's content is hidden so only the material is measured
 * (the same method as glass-ghost.spec.ts, which runs at density 1 and 3 over every surface). `GHOST` lines print the numbers.
 */
const GHOST_MAX = 0.02;
for (const theme of ["ink", "paper"]) for (const level of [2, 3, 4]) {
  test(`palette glass hides the text behind it: card level ${level}, ${theme}, DPR 2`, async ({ browser }) => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    const page = await ctx.newPage();
    await page.goto(`${URL(theme)}&bg=soft&card=${level}`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(800);
    await denseText(page);
    await page.keyboard.press(PALETTE_KEY);
    await page.waitForSelector(".palette:not([hidden])");
    await page.waitForTimeout(700);
    const box = (await page.locator(".palette").boundingBox())!;
    const clip = { x: box.x + 2, y: box.y + 2, width: box.width - 4, height: box.height - 4 };
    await page.evaluate(() => { for (const c of document.querySelectorAll<HTMLElement>(".palette *")) c.style.visibility = "hidden"; });
    const through = await page.screenshot({ clip });
    await page.evaluate(() => { document.querySelector<HTMLElement>(".palette")!.style.visibility = "hidden"; document.getElementById("scrim")!.style.visibility = "hidden"; });
    const bare = await page.screenshot({ clip });
    const ratio = await ghost(page, through, bare);
    console.log(`GHOST palette | level ${level} | ${theme} | dpr 2 | ${ratio.toFixed(4)}`);
    expect(ratio).toBeLessThan(GHOST_MAX);
    await ctx.close();
  });
}

test("the palette's blur is at least 1.5x a terminal line at every card level that has glass", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [level, name] of [[2, "tinted"], [3, "clear"], [4, "frosted"]] as const) {
    await page.goto(`${URL("ink")}&card=${level}`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.keyboard.press(PALETTE_KEY);
    await expect(page.locator(".palette")).toBeVisible();
    const blur = await page.locator(".palette").evaluate((el) => Number(/blur\((\d+(?:\.\d+)?)px\)/.exec(getComputedStyle(el).backdropFilter)?.[1] ?? 0));
    expect(blur, `${name} blur`).toBeGreaterThanOrEqual(27);
  }
  await page.goto(`${URL("ink")}&card=1`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.keyboard.press(PALETTE_KEY);
  await expect(page.locator(".palette")).toBeVisible();
  // Solid paints no glass, so it pays no blur.
  expect(await page.locator(".palette").evaluate((el) => getComputedStyle(el).backdropFilter)).toMatch(/^(none|blur\(0px\))/);
});
