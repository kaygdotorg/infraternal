/**
 * Settings option rows never collide (TASTE: "Text never collides"). In every Settings list that uses the shared choice
 * row (appearance, window sizes) an option's name is one line and never meets its hint, at 375 and 393 px phones and on
 * desktop, in the ink and paper themes. A list reads as one: when any row's hint does not fit beside its name, every row of
 * that list puts the hint under the name, left-aligned with it; otherwise every hint is beside its name. Each section's own
 * list must be on screen before anything is measured, so the spec cannot pass on the wrong view.
 * Alignment (owner, 2026-11-02, #306: "Paper (left aligned) ... light (right aligned)... if the width is smaller ... 'light'
 * becomes a subtitle to Paper"): names are left, descriptions right-aligned and ending at one x in every row, selected or
 * not, before the tick's own fixed column; when the list is too narrow every description is a left-aligned subtitle on
 * its name's x and no name is truncated. Rows start on their heading's left edge, and the names of every list in a window
 * share one left edge (the swatch's place is reserved only where the window has a swatch list). All within 0.5 px.
 * Section headings sit one shared gap above their first row (`--ui-heading-gap`, packages/ui), in every heading style
 * the package has.
 * Review screenshots land in the external job evidence directory.
 */
import { paletteOpen } from "./settings-palette";
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { uiFactor } from "./ui-factor";

const captures = tracerEvidencePath("settings-rows");
const SIZES = [{ w: 375, h: 667, touch: true, dpr: 3 }, { w: 393, h: 852, touch: true, dpr: 3 }, { w: 1440, h: 900, touch: false, dpr: 2 }] as const;
/** Each window (Settings in rows of windows, #304), the palette words that open it, and a list that proves the section is the one on screen. */
const SECTIONS = [
  { name: "Theme", words: "Appearance › Theme", target: "appearance.theme", list: "Theme" },
  { name: "Layout", words: "Appearance › Layout", target: "appearance.layout", list: "Phones" },
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
  const rowEl = t.closest(".ui-sp-row")!, list = t.closest(".ui-sp-list")!;
  const text = t.getBoundingClientRect(), tickEl = rowEl.querySelector(".ui-sp-tick")!, tickRect = tickEl.getBoundingClientRect();
  // An unselected tick is drawn scaled down (its reveal animation), which shrinks its rect around its centre: measure the
  // column it occupies in the layout, its centre and its used width.
  const tickHalf = (parseFloat(getComputedStyle(tickEl).width) || 0) / 2, tickMid = tickRect.left + tickRect.width / 2;
  return {
    window: t.closest(".ui-window")?.getAttribute("data-window-id") ?? "", mode: list.hasAttribute("data-stacked") ? "stacked" : "beside",
    headingLeft: list.previousElementSibling!.getBoundingClientRect().left, rowLeft: row.left, firstLeft: rowEl.firstElementChild!.getBoundingClientRect().left,
    tickLeft: tickMid - tickHalf, tickRight: tickMid + tickHalf, textRight: text.right, labelRight: l.right, truncated: label.scrollWidth > label.clientWidth + 0.5 || getComputedStyle(label).textOverflow === "ellipsis",
    list: t.closest(".ui-sp-list")!.getAttribute("aria-label")!, name: label.textContent!, hint: hint.textContent!, hasHint, labelH: l.height, line, clipped: label.scrollWidth > label.clientWidth + 1,
    overlap: hasHint && l.left < h.right && h.left < l.right && l.top < h.bottom && h.top < l.bottom,
    stacked: hasHint && h.top >= l.bottom - 1, hintLeft: h.left, labelLeft: l.left, rowW: row.width, rowRight: row.right, hintRight: h.right, hintH: h.height,
  };
}));

for (const theme of ["ink", "paper"]) for (const { w, h, touch, dpr } of SIZES) test(`settings rows ${theme} ${w}x${h}: names are one line and never meet their hints`, async ({ browser }) => {
  test.setTimeout(120_000);
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, deviceScaleFactor: dpr });
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
        await paletteOpen(page, section.words, section.target);
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
      const spread = (xs: number[]): number => Math.max(...xs) - Math.min(...xs);
      for (const name of new Set(list.map((r) => r.list))) {
        const own = list.filter((r) => r.list === name);
        // Beside their names the descriptions are right-aligned: one right edge for the list, whatever the length of each
        // description or name, and clear of the tick's own column (a selected row ends where an unselected one does).
        const beside = own.filter((r) => r.hasHint && !r.stacked);
        if (beside.length > 1) expect(spread(beside.map((r) => r.hintRight)), `${section.name}/${name}: descriptions share one right edge`).toBeLessThanOrEqual(0.5);
        for (const r of beside) expect(r.hintRight, `${section.name}/${r.name}: the description ends before the tick column`).toBeLessThanOrEqual(r.tickLeft + 0.5);
        expect(spread(own.map((r) => r.tickRight)), `${section.name}/${name}: the tick has one fixed column`).toBeLessThanOrEqual(0.5);
        for (const r of own) expect(Math.abs(r.tickRight - r.rowRight), `${section.name}/${r.name}: the tick column is the row's far right`).toBeLessThanOrEqual(0.5);
        // Under their names, subtitles sit on the name's own x (asserted per row above) and nothing is truncated.
        for (const r of own) {
          expect(r.truncated, `${section.name}/${r.name}: the name is never truncated`).toBe(false);
          expect(r.labelRight, `${section.name}/${r.name}: the name fits its column`).toBeLessThanOrEqual(r.textRight + 0.5);
        }
        expect(spread(own.map((r) => r.labelLeft)), `${section.name}/${name}: names share one left edge`).toBeLessThanOrEqual(0.5);
        // Rows start on their heading's left edge: no extra indent.
        for (const r of own) {
          expect(Math.abs(r.rowLeft - r.headingLeft), `${section.name}/${r.name}: the row starts on its heading's left edge`).toBeLessThanOrEqual(0.5);
          expect(Math.abs(r.firstLeft - r.headingLeft), `${section.name}/${r.name}: its first mark (swatch, or the name) sits on that edge`).toBeLessThanOrEqual(0.5);
        }
      }
      // Names share one left edge across every list of one window, and a window without swatches leaves no empty slot.
      for (const win of new Set(list.map((r) => r.window))) {
        const inWindow = list.filter((r) => r.window === win);
        expect(spread(inWindow.map((r) => r.labelLeft)), `${section.name}/${win}: names of every list in the window share one left edge`).toBeLessThanOrEqual(0.5);
        for (const r of inWindow.filter((x) => x.list === "Phones" || x.list === "Desktop")) expect(Math.abs(r.labelLeft - r.headingLeft), `${section.name}/${r.name}: no empty swatch slot`).toBeLessThanOrEqual(0.5);
      }
      // The whole list decides together, and by the list's width: phones stack the long Window Sizes descriptions under
      // their names; Theme's one-word descriptions stay beside at every width we ship.
      if (section.name === "Layout" && w < 600) for (const r of list.filter((x) => x.list === "Phones")) expect(r.mode, `${r.name}: narrow lists show subtitles`).toBe("stacked");
      if (section.name === "Theme") for (const r of list.filter((x) => x.list === "Theme")) expect(r.mode, `${r.name}: short descriptions stay beside`).toBe("beside");
      // The heading sits the shared gap above the first row: the gap is the heading's own bottom padding.
      const gap = await page.evaluate((listName) => {
        const l = document.querySelector(`.ui-sp-list[aria-label="${listName}"]`)!;
        const h = l.previousElementSibling as HTMLElement;
        return {
          heading: h.className, padding: parseFloat(getComputedStyle(h).paddingBottom), between: l.getBoundingClientRect().top - h.getBoundingClientRect().bottom,
          // The token holds a rem length: resolve it to pixels through a probe, and report the factor it is measured against.
          token: (() => { const p = document.createElement("div"); p.style.cssText = "position:absolute;visibility:hidden;padding-bottom:var(--ui-heading-gap)"; document.body.append(p); const px = parseFloat(getComputedStyle(p).paddingBottom); p.remove(); return px; })(),
          factor: parseFloat(getComputedStyle(document.documentElement).fontSize) / 16,
        };
      }, section.list);
      expect(gap.heading, `${section.name}: the list follows its heading`).toContain("ui-ts-title");
      expect(gap.token, `${section.name}: the heading gap token is 8 px at the standard size`).toBeCloseTo(8 * gap.factor, 2);
      expect(Math.abs(gap.padding - gap.token), `${section.name}: heading gap equals the token`).toBeLessThanOrEqual(0.5);
      expect(Math.abs(gap.between), `${section.name}: nothing but the heading's own padding sits between it and its list`).toBeLessThanOrEqual(0.5);
      await page.screenshot({ path: resolve(captures, `${section.name.replace(/ /g, "-").toLowerCase()}-${theme}-${w}x${h}.png`) });
      // 2× crop of the section's own window, for the review of the alignment by eye.
      await page.locator(`.ui-window:has(.ui-sp-list[aria-label="${section.list}"])`).first().screenshot({ path: resolve(captures, `${section.name.replace(/ /g, "-").toLowerCase()}-${theme}-${w}x${h}-window.png`) }).catch(() => undefined);
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
  const factor = await uiFactor(page);
  for (const pad of pads) {
    expect(parseFloat(pad.top), `${pad.cls}: 6 px above (times the UI factor)`).toBeCloseTo(6 * factor, 2);
    expect(parseFloat(pad.bottom), `${pad.cls}: the shared gap below`).toBeCloseTo(8 * factor, 2);
  }
});
