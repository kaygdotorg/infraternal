/**
 * Tooltips fit their text (#310, TASTE "A tooltip is as wide as its text").
 *
 * Every control that carries a warm tooltip (icon-only buttons and anything with `data-tip`: the window header's split,
 * close and new-window buttons, the lock, the top pill, the toolbar, the sidebar's own buttons) is hovered, and the open
 * tooltip must show its whole label: no ellipsis, no clipped glyph (`scrollWidth <= clientWidth` on the label and the
 * surface, and every glyph box inside the surface's content box), and the surface must lie inside the viewport. It runs
 * at a desktop (1440×900), a phone (393×852) and at the largest UI size, because the bug that prompted it (the surface
 * measured with a pixel allowance that went stale when padding became rem-based) shows up only as the root font grows.
 * A second test gives a control an over-long label near the screen edge: the tooltip wraps at its cap, never ellipsizes,
 * and shifts to stay on screen.
 *
 * The pointer is a mouse (hover). A long press on touch shows the same surface through the same code path.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("tooltip-fit");
mkdirSync(OUT, { recursive: true });

const CASES = [
  { name: "desktop 1440x900", width: 1440, height: 900, size: undefined },
  { name: "phone 393x852", width: 393, height: 852, size: undefined },
  { name: "desktop at the largest UI size", width: 1440, height: 900, size: "150" },
] as const;

async function open(page: Page, width: number, height: number, size: string | undefined): Promise<void> {
  if (size) await page.addInitScript((value) => localStorage.setItem("tracer.ui-size.v2", value), size);
  await page.setViewportSize({ width, height });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
}

/** Marks every currently reachable tooltip trigger with `data-tipfit` and returns "region|label" for each (the same rule the tooltip's own trigger lookup uses). */
const markTriggers = (page: Page): Promise<string[]> => page.evaluate(() => {
  const found: string[] = [];
  document.querySelectorAll("[data-tipfit]").forEach((e) => e.removeAttribute("data-tipfit"));
  for (const el of document.querySelectorAll<HTMLElement>("[data-tip], button[aria-label], a[aria-label]")) {
    if (el instanceof SVGElement || el.closest("[data-tip-off]") || el.closest(".tip-pos")) continue;
    if (!el.dataset.tip && [...el.childNodes].some((n) => (n.nodeType === 3 ? n.textContent!.trim() : n instanceof HTMLElement && !(n instanceof SVGElement) && n.textContent?.trim()))) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2 || r.left < 0 || r.top < 0 || r.right > innerWidth || r.bottom > innerHeight) continue;
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!hit || !(el === hit || el.contains(hit))) continue;
    const region = el.closest("#sidebar") ? "sidebar" : el.closest(".ui-window-actions") ? "window actions" : el.closest(".ui-window") ? "window" : el.closest("[class*='toolbar'], [class*='keytray'], #keybar") ? "toolbar" : "page";
    const label = el.dataset.tip || el.getAttribute("aria-label") || "";
    el.dataset.tipfit = String(found.length);
    found.push(`${region}|${label}`);
  }
  return found;
});

interface Fit { text: string; expected: string; labelFits: boolean; surfaceFits: boolean; glyphsInside: boolean; ellipsis: boolean; inViewport: boolean; lines: number; box: { x: number; y: number; width: number; height: number } }

/** Hovers marker `index`, waits for its tooltip, lets the pop finish, and reads back how the label sits in the surface. */
async function hoverAndMeasure(page: Page, index: number): Promise<Fit> {
  const sel = `[data-tipfit="${index}"]`;
  await page.mouse.move(2, 2);
  await page.waitForTimeout(120);
  const box = (await page.locator(sel).boundingBox())!;
  await page.mouse.move(box.x + box.width / 2 - 3, box.y + box.height / 2);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 3 });
  await page.waitForFunction((s) => {
    const el = document.querySelector<HTMLElement>(s)!;
    const label = document.querySelector<HTMLElement>(".tip-pos[style*='visible'] .tip-label:not(.is-leaving)");
    return !!label && label.textContent === (el.dataset.tip || el.getAttribute("aria-label"));
  }, sel, { timeout: 4000 });
  await page.waitForTimeout(260);
  return page.evaluate((s) => {
    const el = document.querySelector<HTMLElement>(s)!;
    const label = document.querySelector<HTMLElement>(".tip-pos[style*='visible'] .tip-label:not(.is-leaving)")!;
    const surface = label.closest<HTMLElement>(".tip")!;
    const cs = getComputedStyle(surface);
    const inner = new DOMRect(
      surface.getBoundingClientRect().left + parseFloat(cs.borderLeftWidth) + parseFloat(cs.paddingLeft),
      surface.getBoundingClientRect().top,
      surface.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight),
      surface.getBoundingClientRect().height,
    );
    const range = document.createRange();
    range.selectNodeContents(label);
    const rects = [...range.getClientRects()];
    const s2 = surface.getBoundingClientRect();
    const lineHeight = parseFloat(getComputedStyle(label).lineHeight);
    return {
      text: label.textContent ?? "",
      expected: el.dataset.tip || el.getAttribute("aria-label") || "",
      // scroll* and client* are rounded to whole pixels separately, so a wrapped label of fractional height reads 1 px over.
      labelFits: label.scrollWidth <= label.clientWidth + 1 && label.scrollHeight <= label.clientHeight + 1,
      surfaceFits: surface.scrollWidth <= surface.clientWidth && surface.scrollHeight <= surface.clientHeight,
      glyphsInside: rects.every((r) => r.left >= inner.left - 0.5 && r.right <= inner.right + 0.5),
      ellipsis: cs.textOverflow === "ellipsis" || getComputedStyle(label).textOverflow === "ellipsis",
      inViewport: s2.left >= 0 && s2.top >= 0 && s2.right <= innerWidth && s2.bottom <= innerHeight,
      lines: Math.round(label.getBoundingClientRect().height / lineHeight),
      box: { x: s2.x, y: s2.y, width: s2.width, height: s2.height },
    };
  }, sel);
}

function expectFits(fit: Fit, what: string): void {
  expect.soft(fit.text, `${what}: the label is the control's name`).toBe(fit.expected);
  expect.soft(fit.labelFits, `${what}: label scrolls (clipped)`).toBe(true);
  expect.soft(fit.surfaceFits, `${what}: surface scrolls (clipped)`).toBe(true);
  expect.soft(fit.glyphsInside, `${what}: a glyph sits outside the surface's content box`).toBe(true);
  expect.soft(fit.inViewport, `${what}: the surface leaves the viewport ${JSON.stringify(fit.box)}`).toBe(true);
}

for (const c of CASES) {
  test(`every tooltip shows its whole label: ${c.name}`, async ({ page }) => {
    test.setTimeout(240_000);
    await open(page, c.width, c.height, c.size);
    const seen = new Map<string, Fit>();
    const regions = new Set<string>();
    // Pass 1: the canvas (window headers, view pills, toolbar). Pass 2: with the sidebar open (its own buttons).
    for (const pass of ["canvas", "sidebar"]) {
      if (pass === "sidebar") {
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator("#sidebar")).toBeVisible();
        await page.waitForTimeout(700);
      }
      const triggers = await markTriggers(page);
      // One hover per distinct control name and place; identical windows share one.
      const todo = new Map<string, number>();
      triggers.forEach((t, i) => { if (!todo.has(t) && !seen.has(t)) todo.set(t, i); });
      for (const [key, index] of todo) {
        const fit = await hoverAndMeasure(page, index);
        seen.set(key, fit);
        regions.add(key.split("|")[0]!);
        // Review evidence: the control and its tooltip, for a person to read (the assertions above are not a taste judgement).
        const anchor = (await page.locator(`[data-tipfit="${index}"]`).boundingBox())!;
        const x = Math.max(0, Math.min(fit.box.x, anchor.x) - 12), y = Math.max(0, Math.min(fit.box.y, anchor.y) - 12);
        const right = Math.min(c.width, Math.max(fit.box.x + fit.box.width, anchor.x + anchor.width) + 12), bottom = Math.min(c.height, Math.max(fit.box.y + fit.box.height, anchor.y + anchor.height) + 12);
        await page.screenshot({ path: resolve(OUT, `${c.width}-${c.size ?? "100"}-${key.replace(/[^a-z0-9]+/gi, "-").slice(0, 48)}.png`), clip: { x, y, width: right - x, height: bottom - y } });
        expectFits(fit, `${c.name} / ${key}`);
        // The surface stays one element in the page: other specs, and any caller, find it by `.tip`.
        await expect(page.locator(".tip"), "exactly one .tip in the page").toHaveCount(1);
      }
    }
    console.log(`${c.name}: ${seen.size} tooltips checked in ${[...regions].join(", ")}`);
    // The groups the owner named must really have been covered, not silently filtered out.
    expect(regions.has("window actions"), "window split / close buttons were hovered").toBe(true);
    const labels = [...seen.keys()].map((k) => k.split("|")[1]);
    // A narrow header folds its actions into "More" (TASTE: phone headers carry few actions); a wide one shows them all.
    for (const needed of c.width >= 1000 ? ["Split right", "Split down", "Close"] : ["More"]) expect(labels, needed).toContain(needed);
    await page.mouse.move(2, 2);
  });
}

test("an over-long label wraps at its cap, never ellipsizes, and shifts to stay on screen", async ({ page }) => {
  test.setTimeout(120_000);
  await open(page, 393, 852, undefined);
  const triggers = await markTriggers(page);
  // The control nearest each side of the screen exercises the shift; the first one exercises the wrap in the middle.
  const lefts = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>("[data-tipfit]")].map((e, i) => ({ i, x: e.getBoundingClientRect().left + e.getBoundingClientRect().width / 2 })));
  expect(triggers.length).toBeGreaterThan(2);
  const leftmost = lefts.reduce((a, b) => (b.x < a.x ? b : a)).i;
  const rightmost = lefts.reduce((a, b) => (b.x > a.x ? b : a)).i;
  const LONG = "A deliberately long label that must wrap onto several lines instead of being cut off with an ellipsis anywhere";
  for (const index of [leftmost, rightmost]) {
    await page.evaluate((i) => { document.querySelector<HTMLElement>(`[data-tipfit="${i}"]`)!.dataset.tip = "A deliberately long label that must wrap onto several lines instead of being cut off with an ellipsis anywhere"; }, index);
    const fit = await hoverAndMeasure(page, index);
    expect(fit.text).toBe(LONG);
    expectFits(fit, `long label on control ${index}`);
    expect(fit.ellipsis, "no ellipsis").toBe(false);
    expect(fit.lines, "it wrapped").toBeGreaterThan(1);
    const rem = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize));
    expect(fit.box.width, "it stops at its cap").toBeLessThanOrEqual(17.5 * rem + 1);
    await page.screenshot({ path: resolve(OUT, `long-label-${index === leftmost ? "left" : "right"}.png`) });
  }
});
