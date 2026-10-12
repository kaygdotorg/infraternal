/**
 * Settings option rows never collide (TASTE: "Text never collides"). In every Settings list that uses the shared choice
 * row (appearance, window sizes) an option's name is one line and never meets its hint, at 375 and 393 px phones and on
 * desktop, in the ink and paper themes. A hint that does not fit beside its name moves under it, left-aligned with the name.
 * Captures land in captures/settings-rows.
 */
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = resolve(import.meta.dirname, "../captures/settings-rows");
const SIZES = [{ w: 375, h: 667, touch: true }, { w: 393, h: 852, touch: true }, { w: 1440, h: 900, touch: false }] as const;
const SECTIONS = ["Appearance", "Window Sizes"] as const;

/** Every option row's name and hint geometry, in CSS pixels. */
const rows = (page: Page) => page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-sp-row .ui-sp-text")].map((t) => {
  const label = t.querySelector<HTMLElement>(".ui-sp-label")!, hint = t.querySelector<HTMLElement>(".ui-sp-hint")!;
  const l = label.getBoundingClientRect(), h = hint.getBoundingClientRect(), row = t.closest(".ui-sp-row")!.getBoundingClientRect();
  const line = parseFloat(getComputedStyle(label).lineHeight) || parseFloat(getComputedStyle(label).fontSize) * 1.3;
  const hasHint = hint.textContent !== "";
  return {
    name: label.textContent!, hint: hint.textContent!, hasHint, labelH: l.height, line, clipped: label.scrollWidth > label.clientWidth + 1,
    overlap: hasHint && l.left < h.right && h.left < l.right && l.top < h.bottom && h.top < l.bottom,
    stacked: hasHint && h.top >= l.bottom - 1, hintLeft: h.left, labelLeft: l.left, rowW: row.width, rowRight: row.right, hintRight: h.right, hintH: h.height,
  };
}));

for (const theme of ["ink", "paper"]) for (const { w, h, touch } of SIZES) test(`settings rows ${theme} ${w}x${h}: names are one line and never meet their hints`, async ({ browser }) => {
  test.setTimeout(120_000);
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, deviceScaleFactor: touch ? 3 : 1 });
  const page = await context.newPage();
  try {
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
    await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
    await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
    await page.waitForTimeout(1000);
    for (const section of SECTIONS) {
      await page.keyboard.press("Control+Shift+K");
      await page.keyboard.type(`settings: ${section.toLowerCase()}`);
      await page.keyboard.press("Enter");
      await expect(page.locator(".ui-sp-row").first()).toBeAttached({ timeout: 10_000 });
      await page.waitForTimeout(1500);
      const list = await rows(page);
      expect(list.length, `${section} has option rows`).toBeGreaterThan(2);
      for (const r of list) {
        expect(r.overlap, `${section}/${r.name}: name meets hint`).toBe(false);
        expect(r.clipped, `${section}/${r.name}: name is clipped`).toBe(false);
        expect(r.labelH, `${section}/${r.name}: name is one line`).toBeLessThan(r.line * 1.6);
        if (r.hasHint) expect(r.hintRight, `${section}/${r.name}: hint stays inside the row`).toBeLessThanOrEqual(r.rowRight + 0.5);
        if (r.stacked) expect(Math.abs(r.hintLeft - r.labelLeft), `${section}/${r.name}: stacked hint aligns with the name`).toBeLessThan(1.5);
      }
      await page.screenshot({ path: resolve(captures, `${section.replace(/ /g, "-").toLowerCase()}-${theme}-${w}x${h}.png`) });
    }
  } finally { await context.close(); }
});
