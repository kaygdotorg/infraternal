/**
 * Pixel measures for the TASTE row "Glass shows colour, never legible text": can a person still read characters through
 * a glass card, and does the card still show colour and shape from behind it?
 *
 * Two screenshots of the same page are compared: one with the card, one with the card (and its glass bed) hidden, so the
 * unblurred content behind it is fully visible. The whole card is measured, rim included (inset 2 px so only its own 1 px
 * border and edge antialiasing are left out), inside its rounded corners, and with the card's own text and buttons masked.
 *
 * - `measureLegibility` high-passes both pictures (the picture minus a small box blur of itself), which keeps strokes and
 *   edges and drops colour and soft shapes, and correlates them. About 0: the glass turned text into colour and shape.
 *   Towards 1: strokes survive. Colour showing through adds only low frequencies, so this never demands an opaque card.
 *   It reports the whole card (`corr`), the outer 14 px rim (`ringCorr`), and the stroke energy behind the card
 *   (`behindRms`), which a test must see above a floor or it proved nothing.
 * - `measureColour` low-passes both pictures (a wide box blur, per colour channel) and correlates them. Over a coloured
 *   block behind the card, glass shows the block's colours and shapes (clearly above 0); an opaque card shows none (about 0).
 */
import type { Page } from "playwright/test";

/** The legibility numbers for one card, see the module note. */
export interface Legibility { corr: number; ringCorr: number; innerCorr: number; behindRms: number; shownRms: number; pixels: number }

/** The kind of comparison: high-pass keeps strokes (text), low-pass keeps colour and shape. */
type Band = "strokes" | "colour";

/** Shared pixel work, run in the page. `band` picks the filter; the result carries all the numbers each caller needs. */
async function measure(page: Page, withCard: Buffer, withoutCard: Buffer, band: Band): Promise<Legibility> {
  return await page.evaluate(async ({ a, b, band }) => {
    const tip = document.querySelector<HTMLElement>(".ui-confirm-tip")!;
    const box = tip.getBoundingClientRect();
    const radius = parseFloat(getComputedStyle(tip).borderTopLeftRadius) || 14;
    // Everything the card draws itself is excluded (padded 4 px for antialiasing), so only the glass is measured.
    const own = [...tip.querySelectorAll<HTMLElement>(".ui-confirm-tip-message, .ui-confirm-tip-detail, button")].map((element) => element.getBoundingClientRect());
    const load = async (data: string): Promise<ImageData> => {
      const image = await createImageBitmap(await (await fetch(`data:image/png;base64,${data}`)).blob());
      const canvas = new OffscreenCanvas(image.width, image.height);
      const context = canvas.getContext("2d")!;
      context.drawImage(image, 0, 0);
      return context.getImageData(0, 0, image.width, image.height);
    };
    const [withImage, withoutImage] = [await load(a), await load(b)];
    const scale = withImage.width / innerWidth;
    // The whole card: inset 2 px (its own border), and only inside the rounded corners.
    const left = Math.round((box.left + 2) * scale), top = Math.round((box.top + 2) * scale);
    const w = Math.round((box.width - 4) * scale), h = Math.round((box.height - 4) * scale);
    const r = (radius - 2) * scale;
    // Distance from the card's edge, in CSS px, or -1 outside the rounded rectangle.
    const edgeDistance = (x: number, y: number): number => {
      const cx = Math.min(Math.max(x, r), w - r), cy = Math.min(Math.max(y, r), h - r);
      if (Math.hypot(x - cx, y - cy) > r) return -1;
      return Math.min(x, y, w - 1 - x, h - 1 - y) / scale;
    };
    const channels = (image: ImageData): Float32Array[] => [0, 1, 2].map((channel) => {
      const out = new Float32Array(w * h);
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) out[y * w + x] = image.data[((top + y) * image.width + left + x) * 4 + channel]!;
      return out;
    });
    const luminance = (image: ImageData): Float32Array[] => {
      const [red, green, blue] = channels(image);
      const out = new Float32Array(w * h);
      for (let i = 0; i < w * h; i++) out[i] = 0.2126 * red![i]! + 0.7152 * green![i]! + 0.0722 * blue![i]!;
      return [out];
    };
    // A box blur through an integral image.
    const boxBlur = (values: Float32Array, radiusPx: number): Float32Array => {
      const integral = new Float64Array((w + 1) * (h + 1));
      for (let y = 0; y < h; y++) {
        let row = 0;
        for (let x = 0; x < w; x++) { row += values[y * w + x]!; integral[(y + 1) * (w + 1) + x + 1] = integral[y * (w + 1) + x + 1]! + row; }
      }
      const out = new Float32Array(w * h);
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const x0 = Math.max(0, x - radiusPx), x1 = Math.min(w, x + radiusPx + 1), y0 = Math.max(0, y - radiusPx), y1 = Math.min(h, y + radiusPx + 1);
        out[y * w + x] = (integral[y1 * (w + 1) + x1]! - integral[y0 * (w + 1) + x1]! - integral[y1 * (w + 1) + x0]! + integral[y0 * (w + 1) + x0]!) / ((x1 - x0) * (y1 - y0));
      }
      return out;
    };
    // Strokes: the picture minus its own small blur (about 2 CSS px). Colour: the picture blurred wide (about 12 CSS px).
    const filter = (planes: Float32Array[]): Float32Array[] => planes.map((plane) => {
      if (band === "strokes") { const soft = boxBlur(plane, Math.max(2, Math.round(2 * scale))); return plane.map((value, i) => value - soft[i]!); }
      return boxBlur(plane, Math.round(12 * scale));
    });
    const sourceOf = (image: ImageData): Float32Array[] => (band === "strokes" ? luminance(image) : channels(image));
    const filteredWith = filter(sourceOf(withImage)), filteredWithout = filter(sourceOf(withoutImage));
    const counted = new Uint8Array(w * h).fill(1);
    for (const rect of own) {
      const x0 = Math.max(0, Math.round((rect.left - 4) * scale) - left), x1 = Math.min(w, Math.round((rect.right + 4) * scale) - left);
      const y0 = Math.max(0, Math.round((rect.top - 4) * scale) - top), y1 = Math.min(h, Math.round((rect.bottom + 4) * scale) - top);
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) counted[y * w + x] = 0;
    }
    // Correlation over a set of pixels (all planes together, so a colour comparison weighs the three channels).
    const correlation = (select: (distance: number) => boolean): { corr: number; aa: number; bb: number; n: number } => {
      let saa = 0, sbb = 0, sab = 0, n = 0;
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const i = y * w + x;
        if (!counted[i]) continue;
        const distance = edgeDistance(x, y);
        if (distance < 0 || !select(distance)) continue;
        n++;
        for (let p = 0; p < filteredWith.length; p++) { const va = filteredWith[p]![i]!, vb = filteredWithout[p]![i]!; saa += va * va; sbb += vb * vb; sab += va * vb; }
      }
      return { corr: saa > 0 && sbb > 0 ? sab / Math.sqrt(saa * sbb) : 0, aa: saa, bb: sbb, n };
    };
    // A colour comparison is of the shapes, so the means are taken out: a flat card over a coloured block must read as about 0.
    if (band === "colour") {
      const mean = (planes: Float32Array[]): number[] => planes.map((plane) => { let s = 0, c = 0; for (let i = 0; i < w * h; i++) if (counted[i] && edgeDistance(i % w, Math.floor(i / w)) >= 0) { s += plane[i]!; c++; } return c ? s / c : 0; });
      const [mA, mB] = [mean(filteredWith), mean(filteredWithout)];
      filteredWith.forEach((plane, p) => { for (let i = 0; i < plane.length; i++) plane[i] = plane[i]! - mA[p]!; });
      filteredWithout.forEach((plane, p) => { for (let i = 0; i < plane.length; i++) plane[i] = plane[i]! - mB[p]!; });
    }
    const full = correlation(() => true), ring = correlation((d) => d <= 14), inner = correlation((d) => d > 14);
    const planes = filteredWith.length;
    return {
      corr: full.corr, ringCorr: ring.corr, innerCorr: inner.corr,
      behindRms: Math.sqrt(full.bb / Math.max(1, full.n * planes)), shownRms: Math.sqrt(full.aa / Math.max(1, full.n * planes)), pixels: full.n,
    };
  }, { a: withCard.toString("base64"), b: withoutCard.toString("base64"), band });
}

/**
 * How legible the text behind `.ui-confirm-tip` is through the whole card, rim included.
 * `withCard` and `withoutCard` are PNG screenshots of the same page, taken at rest, with and without the card showing.
 */
export async function measureLegibility(page: Page, withCard: Buffer, withoutCard: Buffer): Promise<Legibility> {
  return await measure(page, withCard, withoutCard, "strokes");
}

/**
 * How much colour and shape from behind the card shows through it (`corr`), over a coloured block placed behind it:
 * clearly above 0 for glass, about 0 for an opaque card.
 */
export async function measureColour(page: Page, withCard: Buffer, withoutCard: Buffer): Promise<Legibility> {
  return await measure(page, withCard, withoutCard, "colour");
}
