/**
 * Pixel measurement of text on glass, shared by the glass contrast specs (D365, #448).
 *
 * `measure` takes every run of text inside one element, reads its colour from the computed style, and reads what is behind
 * it from a screenshot taken with every glyph made transparent, so blur, saturation, the glass bed and the page behind are
 * all in the number. A hover tooltip over the element has its own glyphs hidden too (it is another surface, with its own check). Runs on a theme swatch, and runs outside the element's own box (scrolled out of a clipped list), are skipped. It returns the lowest contrast of each run against the lightest and the darkest pixel under it.
 */
import type { Page } from "playwright/test";

/** One run of text in the popover: what it says, its colour (rgba) and its box on the page. */
export interface Run { text: string; colour: [number, number, number, number]; x: number; y: number; w: number; h: number }
/** The lowest contrast measured for one text run. */
export interface Result { text: string; ratio: number; colour: string }

/** Contrast of every text run in `selector`'s popover against the pixels under it; the lowest first. */
export async function measure(page: Page, selector: string): Promise<Result[] & { hidden: Buffer }> {
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
      // A theme swatch is a picture of another theme's colours, not text on the glass.
      if (parent.closest(".swatch")) continue;
      const range = document.createRange();
      range.selectNodeContents(n);
      const r = range.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) continue;
      // Scrolled out of a clipped list: not on screen, so nobody reads it.
      const rootBox = root.getBoundingClientRect();
      if (r.bottom > rootBox.bottom + 1 || r.top < rootBox.top - 1 || r.right > rootBox.right + 1 || r.left < rootBox.left - 1) continue;
      const m = /rgba?\(([^)]+)\)/.exec(style.color) ?? [];
      const [rr = 0, gg = 0, bb = 0, aa = 1] = (m[1] ?? "").split(/[ ,/]+/).filter(Boolean).map(Number);
      out.push({ text, colour: [rr, gg, bb, aa], x: r.x, y: r.y, w: r.width, h: r.height });
    }
    return out;
  }, selector);
  // Hide every glyph so the screenshot holds only what is behind the text.
  const hide = await page.addStyleTag({ content: `${selector}, ${selector} * { color: transparent !important; text-shadow: none !important; -webkit-text-fill-color: transparent !important; } ${selector} svg, .tip svg { visibility: hidden !important; } .tip, .tip * { color: transparent !important; text-shadow: none !important; -webkit-text-fill-color: transparent !important; }` });
  // Two animation frames, not a sleep: the capture must not be taken before the hiding style has painted. On a loaded host a fixed
  // 80 ms was sometimes shorter than a frame, the glyphs were still in the capture, and a white label then measured against its own
  // lightest pixels (1.05:1, and 3.88:1 on a glyph in the full run of #448).
  await page.evaluate(() => new Promise<void>((done) => { requestAnimationFrame(() => { requestAnimationFrame(() => { done(); }); }); }));
  // Captured until two captures in a row are identical: a capture taken before the hiding style reached the screen differs from the
  // next one, so a stale frame can never be the one that is measured.
  let png = await page.screenshot({ clip: box });
  for (let attempt = 0; attempt < 8; attempt++) {
    const again = await page.screenshot({ clip: box });
    if (again.equals(png)) break;
    png = again;
  }
  await hide.evaluate((el) => { (el as unknown as Element).remove(); });
  const dataUrl = `data:image/png;base64,${png.toString("base64")}`;
  const ratios = await page.evaluate(async ({ url, runs, box }) => {
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
  // The capture with every glyph hidden rides along, so a low reading can be looked at: it is what the runs were measured against.
  return Object.assign(ratios, { hidden: png });
}
