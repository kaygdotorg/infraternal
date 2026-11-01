/**
 * Settings option rows never collide (TASTE: "Text never collides"). In every Settings list that uses the shared choice
 * row (appearance, window sizes) an option's name is one line and never meets its hint, at 375 and 393 px phones and on
 * desktop, in the ink and paper themes. A list reads as one: when any row's hint does not fit beside its name, every row of
 * that list puts the hint under the name, left-aligned with it; otherwise every hint is beside its name. Each section's own
 * list must be on screen before anything is measured, so the spec cannot pass on the wrong view.
 * Alignment (owner, 2026-11-01): hints never follow the length of their own name. Beside their names, every hint of a
 * list starts at one x; under their names, at the name's own x; both within 0.5 px. Section headings sit one shared gap
 * above their first row (`--ui-heading-gap`, packages/ui), in every heading style the package has.
 * Review screenshots land in the external job evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("settings-rows");
const SIZES = [{ w: 375, h: 667, touch: true }, { w: 393, h: 852, touch: true }, { w: 1440, h: 900, touch: false }] as const;
/** Each section, the palette words that open it, and a list that proves the section is the one on screen. */
const SECTIONS = [
  { name: "Appearance", words: "settings: appearance", list: "Theme" },
  { name: "Window Sizes", words: "settings: window sizes", list: "Phones" },
] as const;

/** True when the named list exists and lies inside the screen (its column is the one in view). */
const listOnScreen = (page: Page, list: string) => page.evaluate((name) => {
  const n = document.querySelector(`.ui-sp-list[aria-label="${name}"]`);
  if (!n) return false;
  const r = n.getBoundingClientRect();
  return r.left >= 0 && r.right <= innerWidth + 1 && r.top < innerHeight - 40 && r.bottom > 0;
}, list);

/** Every option row's name and hint geometry, in CSS pixels. */
const rows = (page: Page) => page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-sp-row .ui-sp-text")].map((t) => {
  const label = t.querySelector<HTMLElement>(".ui-sp-label")!, hint = t.querySelector<HTMLElement>(".ui-sp-hint")!;
  const l = label.getBoundingClientRect(), h = hint.getBoundingClientRect(), row = t.closest(".ui-sp-row")!.getBoundingClientRect();
  const line = parseFloat(getComputedStyle(label).lineHeight) || parseFloat(getComputedStyle(label).fontSize) * 1.3;
  const hasHint = hint.textContent !== "";
  return {
    list: t.closest(".ui-sp-list")!.getAttribute("aria-label")!, name: label.textContent!, hint: hint.textContent!, hasHint, labelH: l.height, line, clipped: label.scrollWidth > label.clientWidth + 1,
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
    // The test double is shared and occasionally slow to hand the canvas its first windows; reload rather than fail on that.
    for (let attempt = 0; attempt < 3; attempt++) {
      await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
      if (await page.locator("[data-view='console'] .ui-window").nth(3).waitFor({ timeout: 15_000 }).then(() => true, () => false)) break;
    }
    await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
    await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
    await page.waitForTimeout(1000);
    for (const section of SECTIONS) {
      // The palette can swallow the first keys while the canvas settles; retry until this section's list is on screen.
      for (let attempt = 0; attempt < 4; attempt++) {
        await page.keyboard.press("Control+Shift+K");
        await page.keyboard.type(section.words);
        await page.keyboard.press("Enter");
        const onScreen = await expect.poll(() => listOnScreen(page, section.list), { timeout: 5000 }).toBe(true).then(() => true, () => false);
        if (onScreen) break;
      }
      // Its column is the one in view: the list lies inside the screen and starts above the bottom edge (polled: the view scrolls).
      await expect.poll(() => listOnScreen(page, section.list), { message: `${section.name}: its list is on screen`, timeout: 10_000 }).toBe(true);
      await expect(page.locator(`.ui-window:has(.ui-sp-list[aria-label="${section.list}"])`).first().getByText(section.name, { exact: true }).first(), `${section.name}: heading shown`).toBeVisible();
      const list = await rows(page);
      expect(list.length, `${section.name} has option rows`).toBeGreaterThan(2);
      // One decision per list: every row with a hint has it in the same place.
      for (const name of new Set(list.map((r) => r.list))) {
        const hinted = list.filter((r) => r.list === name && r.hasHint);
        expect(new Set(hinted.map((r) => r.stacked)).size, `${section.name}/${name}: hints share one placement`).toBeLessThanOrEqual(1);
      }
      for (const r of list) {
        expect(r.overlap, `${section.name}/${r.name}: name meets hint`).toBe(false);
        expect(r.clipped, `${section.name}/${r.name}: name is clipped`).toBe(false);
        expect(r.labelH, `${section.name}/${r.name}: name is one line`).toBeLessThan(r.line * 1.6);
        if (r.hasHint) expect(r.hintRight, `${section.name}/${r.name}: hint stays inside the row`).toBeLessThanOrEqual(r.rowRight + 0.5);
        if (r.stacked) expect(Math.abs(r.hintLeft - r.labelLeft), `${section.name}/${r.name}: stacked hint aligns with the name`).toBeLessThanOrEqual(0.5);
      }
      // Beside their names: one column per list, whatever the length of each name.
      for (const name of new Set(list.map((r) => r.list))) {
        const beside = list.filter((r) => r.list === name && r.hasHint && !r.stacked).map((r) => r.hintLeft);
        if (beside.length > 1) expect(Math.max(...beside) - Math.min(...beside), `${section.name}/${name}: hints share one left edge`).toBeLessThanOrEqual(0.5);
        const names = list.filter((r) => r.list === name).map((r) => r.labelLeft);
        expect(Math.max(...names) - Math.min(...names), `${section.name}/${name}: names share one left edge`).toBeLessThanOrEqual(0.5);
      }
      // The heading sits the shared gap above the first row: the gap is the heading's own bottom padding.
      const gap = await page.evaluate((listName) => {
        const l = document.querySelector(`.ui-sp-list[aria-label="${listName}"]`)!;
        const h = l.previousElementSibling as HTMLElement;
        return {
          heading: h.className, padding: parseFloat(getComputedStyle(h).paddingBottom), between: l.getBoundingClientRect().top - h.getBoundingClientRect().bottom,
          token: parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--ui-heading-gap")),
        };
      }, section.list);
      expect(gap.heading, `${section.name}: the list follows its heading`).toContain("ui-ts-title");
      expect(gap.token, `${section.name}: the heading gap token is 8 px`).toBe(8);
      expect(Math.abs(gap.padding - gap.token), `${section.name}: heading gap equals the token`).toBeLessThanOrEqual(0.5);
      expect(Math.abs(gap.between), `${section.name}: nothing but the heading's own padding sits between it and its list`).toBeLessThanOrEqual(0.5);
      await page.screenshot({ path: resolve(captures, `${section.name.replace(/ /g, "-").toLowerCase()}-${theme}-${w}x${h}.png`) });
    }
  } finally { await context.close(); }
});

test("every section heading style in packages/ui uses the one heading padding", async ({ page }) => {
  await page.goto("/?mock=1");
  const pads = await page.evaluate(() => ["ui-ts-title", "ui-kv-group", "ui-shortcuts-title"].map((cls) => {
    const probe = document.createElement("div");
    probe.className = cls;
    document.body.append(probe);
    const s = getComputedStyle(probe);
    const out = { cls, top: s.paddingTop, bottom: s.paddingBottom };
    probe.remove();
    return out;
  }));
  for (const pad of pads) {
    expect(pad.top, `${pad.cls}: 6 px above`).toBe("6px");
    expect(pad.bottom, `${pad.cls}: the shared gap below`).toBe("8px");
  }
});
