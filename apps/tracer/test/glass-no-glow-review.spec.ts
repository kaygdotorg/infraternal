/**
 * Review of #448 (D365, job J1020), ask 1: no glow behind text anywhere, on every glass surface, in every theme and look, on a
 * desktop and a phone viewport.
 *
 * For each theme (ten), each size (1440 x 900, 393 x 852) and each material (the card levels Clear and Frosted with no look, and the three looks
 * Tinted, Frosted and Solid) the page is opened, every glass surface the scene has is opened in turn (palette, toast, error toast,
 * confirmation card, and on a desktop the window menu) and, while it is open, the whole document is searched for an element, or a
 * `::before` / `::after` of one, whose computed `text-shadow` is not `none`. A `filter: drop-shadow` or a `-webkit-text-stroke` on text is
 * reported too. The result goes to `no-glow.jsonl`; any hit fails the case.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { glassReady, settled } from "./glass-settled";
import { SIZES, surfacesFor } from "./glass-scenes";

/** Where the table lands. */
const OUT = tracerEvidencePath("glass-no-glow");
mkdirSync(OUT, { recursive: true });

/** The ten themes of `packages/ui/src/themes.ts`. */
const THEMES = ["paper", "ink", "latte", "mocha", "dawn", "rosepine", "nord", "tokyo", "gruvbox", "dracula"] as const;
/** The materials: a card level with no look, and the three looks. */
const MATERIALS = ["&card=3", "&card=4", "&look=tinted", "&look=frosted", "&look=solid"] as const;

/** Elements (and their pseudo-elements) with a text shadow, a text stroke or a drop-shadow filter, in the whole document. */
function glowing(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (const el of document.querySelectorAll<HTMLElement>("*")) {
      for (const pseudo of [null, "::before", "::after"]) {
        const s = getComputedStyle(el, pseudo);
        if (pseudo !== null && s.content === "none") continue;
        const bad = [s.textShadow !== "none" ? `text-shadow ${s.textShadow}` : "", /drop-shadow/.test(s.filter) && el.textContent?.trim() ? `filter ${s.filter}` : "", parseFloat(s.getPropertyValue("-webkit-text-stroke-width")) > 0 ? "text-stroke" : ""].filter(Boolean);
        if (bad.length) out.push(`${el.tagName.toLowerCase()}${pseudo ?? ""}.${String(el.className).slice(0, 40)}: ${bad.join(", ")}`);
      }
    }
    return out;
  });
}

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`${size.id} ${theme}: no text shadow, stroke or glow filter on any open glass surface, in every card level and look`, async ({ browser }) => {
      test.setTimeout(240_000);
      const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 1, ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      const hits: string[] = [];
      for (const material of MATERIALS) {
        await page.goto(`/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=${theme}${material}`);
        await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
        await glassReady(page);
        await page.waitForFunction(() => Boolean(window.__toast && window.__removalCard), null, { timeout: 30_000 });
        await page.waitForFunction(() => Boolean((window as unknown as { __tracerClusters?: unknown }).__tracerClusters), null, { timeout: 30_000 });
        await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
        await page.waitForFunction(() => { const w = document.querySelector(".ui-window"); return w !== null && w.getBoundingClientRect().width > 280; }, null, { timeout: 30_000 });
        await page.evaluate(() => window.__toast!.dismiss());
        const base = await glowing(page);
        for (const surface of surfacesFor(size)) {
          await surface.open(page);
          await expect(page.locator(surface.selector).first()).toBeVisible({ timeout: 8000 });
          await settled(page, surface.selector);
          const found = (await glowing(page)).filter((h) => !base.includes(h));
          if (found.length) hits.push(...found.map((h) => `${material} ${surface.id}: ${h}`));
          await surface.close?.(page);
        }
        if (base.length) hits.push(...base.map((h) => `${material} page: ${h}`));
      }
      appendFileSync(`${OUT}/no-glow.jsonl`, `${JSON.stringify({ size: size.id, theme, hits: [...new Set(hits)] })}\n`);
      expect([...new Set(hits)], `elements with a glow on ${theme} at ${size.id}`).toEqual([]);
      await context.close();
    });
  }
}
