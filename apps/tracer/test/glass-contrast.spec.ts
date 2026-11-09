/**
 * Text on glass over worst-case backdrops (D365, #448): the owner's Send keys case, measured on the rendered pixels.
 *
 * The owner saw the Send keys popover's section labels and key hints as faint grey on light grey over a light app window.
 * This spec opens the #146 mockup's popovers (`appmock=desktop&pop=keys` on a desktop, `appmock=phone-app&pop=gear` on a
 * phone) in Ink (dark) and Paper (light), at every card level (`card=1..4`), over four backdrops: the mockup's own light
 * window, the same picture inverted (a dark window), pure white and pure black. For each text run in the popover it takes the
 * run's own colour from the computed style and its backdrop from a screenshot of the popover with all text made
 * transparent, then asserts the lowest contrast against the lightest and the darkest pixel under the run is at least 4.5:1.
 * Measuring pixels (not tokens) means the check also sees blur, saturation, the glass bed and the page behind, which the unit
 * audit (`packages/ui/src/glass-contrast.test.ts`) does not.
 *
 * Screenshots of every case land in the external evidence directory as `<size>-<scheme>-<backdrop>-card<N>.png`.
 * Needs the preview build, which this config's web server already builds, and the #146 mockup (skipped without it). The mockup marks
 * its window card with `data-glass-under`, the contract that gives a picture's glass the static floor (`packages/ui/src/themes.ts`).
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** The #146 mockup is what these cases open; until it is on this branch they are skipped, and they run the day it lands. */
const HAS_MOCKUP = existsSync(resolve(import.meta.dirname, "../src/canvas/mock/appwin-scenes/mount.on-demand.ts"));
test.skip(!HAS_MOCKUP, "the app-window mockup (#146) is not on this branch");

const OUT = tracerEvidencePath("glass-contrast");
const LINE = 4.5;

interface Size { id: string; width: number; height: number; phone: boolean; query: string; ready: string }
const SIZES: Size[] = [
  { id: "1440x900", width: 1440, height: 900, phone: false, query: "appmock=desktop&pop=keys", ready: ".awm-keys" },
  { id: "393x852", width: 393, height: 852, phone: true, query: "appmock=phone-app&pop=gear", ready: ".awm-gearpop" },
];

/** CSS that turns the mockup's picture into each backdrop; the popover is not inside `.awm-surface`, so it is untouched. */
const BACKDROPS: Record<string, string> = {
  light: "",
  dark: ".awm-surface { filter: invert(1) hue-rotate(180deg) !important; }",
  white: ".awm-surface { filter: brightness(0) invert(1) !important; }",
  black: ".awm-surface { filter: brightness(0) !important; }",
};

interface Run { text: string; colour: [number, number, number, number]; x: number; y: number; w: number; h: number }
interface Result { text: string; ratio: number; colour: string }

/** Contrast of every text run in `selector`'s popover against the pixels under it; the lowest first. */
async function measure(page: Page, selector: string): Promise<Result[]> {
  const box = await page.locator(selector).first().boundingBox();
  if (!box) throw new Error(`${selector} has no box`);
  const runs: Run[] = await page.evaluate((sel) => {
    const root = document.querySelector(sel)!;
    const out: Run[] = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent ?? "").trim();
      const parent = n.parentElement;
      if (!text || !parent) continue;
      const style = getComputedStyle(parent);
      if (style.visibility === "hidden" || Number(style.opacity) === 0) continue;
      const range = document.createRange();
      range.selectNodeContents(n);
      const r = range.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) continue;
      const m = /rgba?\(([^)]+)\)/.exec(style.color) ?? [];
      const [rr = 0, gg = 0, bb = 0, aa = 1] = (m[1] ?? "").split(/[ ,/]+/).filter(Boolean).map(Number);
      out.push({ text, colour: [rr, gg, bb, aa], x: r.x, y: r.y, w: r.width, h: r.height });
    }
    return out;
  }, selector);
  // Hide every glyph so the screenshot holds only what is behind the text.
  const hide = await page.addStyleTag({ content: `${selector}, ${selector} * { color: transparent !important; text-shadow: none !important; -webkit-text-fill-color: transparent !important; } ${selector} svg { visibility: hidden !important; }` });
  // sleep: one frame for the style to paint before the capture
  await page.waitForTimeout(80);
  const png = await page.screenshot({ clip: box });
  await hide.evaluate((el) => el.remove());
  const dataUrl = `data:image/png;base64,${png.toString("base64")}`;
  return page.evaluate(async ({ url, runs, box }) => {
    const img = await createImageBitmap(await (await fetch(url)).blob());
    const scale = img.width / box.width;
    const c = new OffscreenCanvas(img.width, img.height);
    const ctx = c.getContext("2d")!;
    ctx.drawImage(img, 0, 0);
    const lum = (r: number, g: number, b: number): number => {
      const f = (v: number): number => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    return runs.map((run) => {
      const x = Math.max(0, Math.floor((run.x - box.x) * scale)), y = Math.max(0, Math.floor((run.y - box.y) * scale));
      const w = Math.max(1, Math.min(img.width - x, Math.ceil(run.w * scale))), h = Math.max(1, Math.min(img.height - y, Math.ceil(run.h * scale)));
      const px = ctx.getImageData(x, y, w, h).data;
      let lo: number[] = [255, 255, 255], hi: number[] = [0, 0, 0], loL = 2, hiL = -1;
      for (let i = 0; i < px.length; i += 4) {
        const l = lum(px[i]!, px[i + 1]!, px[i + 2]!);
        if (l < loL) { loL = l; lo = [px[i]!, px[i + 1]!, px[i + 2]!]; }
        if (l > hiL) { hiL = l; hi = [px[i]!, px[i + 1]!, px[i + 2]!]; }
      }
      const [tr, tg, tb, ta] = run.colour;
      const ratioOver = (bg: number[]): number => {
        const t = lum(tr * ta + bg[0]! * (1 - ta), tg * ta + bg[1]! * (1 - ta), tb * ta + bg[2]! * (1 - ta));
        const b = lum(bg[0]!, bg[1]!, bg[2]!);
        return (Math.max(t, b) + 0.05) / (Math.min(t, b) + 0.05);
      };
      return { text: run.text, ratio: Math.min(ratioOver(lo), ratioOver(hi)), colour: `rgb(${tr} ${tg} ${tb} / ${ta})` };
    });
  }, { url: dataUrl, runs, box }).then((all) => all.sort((a, b) => a.ratio - b.ratio));
}

for (const size of SIZES) {
  for (const scheme of ["dark", "light"] as const) {
    for (const [backdrop, css] of Object.entries(BACKDROPS)) {
      for (const card of [1, 2, 3, 4]) {
        test(`${size.id} ${scheme === "dark" ? "Ink" : "Paper"} card ${card} over ${backdrop}: every text run reaches ${LINE}:1`, async ({ browser }) => {
          const context = await browser.newContext({
            viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme,
            ...(size.phone ? { hasTouch: true, isMobile: true } : {}),
          });
          const page = await context.newPage();
          await page.goto(`/?mock=1&proto=clusters&fps=0&${size.query}&card=${card}`);
          await expect(page.locator(".awm")).toBeVisible({ timeout: 20_000 });
          await expect(page.locator(size.ready).first()).toBeVisible({ timeout: 8000 });
          if (css) await page.addStyleTag({ content: css });
          await page.evaluate(() => document.fonts.ready);
          // sleep: the popover grows in over 200 ms and the filter's transition runs 200 ms
          await page.waitForTimeout(900);
          await page.screenshot({ path: `${OUT}/${size.id}-${scheme === "dark" ? "ink" : "paper"}-${backdrop}-card${card}.png` });
          const results = await measure(page, size.ready);
          expect(results.length, "text runs found in the popover").toBeGreaterThan(3);
          const worst = results[0]!;
          expect(worst.ratio, `lowest: "${worst.text}" ${worst.colour} ${worst.ratio.toFixed(2)}:1; next: ${results.slice(1, 4).map((r) => `"${r.text}" ${r.ratio.toFixed(2)}`).join(", ")}`).toBeGreaterThanOrEqual(LINE);
          await context.close();
        });
      }
    }
  }
}
