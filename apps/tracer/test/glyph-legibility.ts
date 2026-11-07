/**
 * A pixel measure for the TASTE row "Glass shows colour, never legible text": can a person still read characters
 * through a glass card?
 *
 * Two screenshots of the same page are compared: one with the card, one with the card hidden (the text behind it fully
 * visible). Inside the card, minus the card's own text, both pictures are high-passed (the picture minus a small box
 * blur of itself), which keeps strokes and edges and drops colour and soft shapes. If the strokes of the unblurred text
 * show up in the card's picture, the two high-passed images correlate; if the glass turns them into colour and shape,
 * they do not. Colour showing through is allowed (it adds only low frequencies), so this never demands an opaque card.
 *
 * The result has three numbers:
 * - `corr`: correlation of the two high-passed images, about 0 when nothing legible survives, towards 1 when text does.
 * - `behindRms`: how much stroke energy is behind the card. A test must see this above a floor, or it proved nothing
 *   (a card over a blank part of the terminal would pass any material).
 * - `shownRms`: stroke energy that remains inside the card.
 */
import type { Page } from "playwright/test";

/** The legibility numbers for one card, see the module note. */
export interface Legibility { corr: number; behindRms: number; shownRms: number; pixels: number }

/**
 * Measure how legible the content behind `.ui-confirm-tip` is through the card.
 * `withCard` and `withoutCard` are PNG screenshots of the same page, taken at rest, with and without the card showing.
 */
export async function measureLegibility(page: Page, withCard: Buffer, withoutCard: Buffer): Promise<Legibility> {
  return await page.evaluate(async ({ a, b }) => {
    const tip = document.querySelector<HTMLElement>(".ui-confirm-tip")!;
    const box = tip.getBoundingClientRect();
    // Everything the card draws itself is excluded (padded 4 px for antialiasing), so only the glass is measured.
    const own = [...tip.querySelectorAll<HTMLElement>(".ui-confirm-tip-message, .ui-confirm-tip-detail, button")].map((element) => element.getBoundingClientRect());
    const load = async (data: string): Promise<ImageData> => {
      const image = await createImageBitmap(await (await fetch(`data:image/png;base64,${data}`)).blob());
      const canvas = new OffscreenCanvas(image.width, image.height);
      const context = canvas.getContext("2d")!;
      context.drawImage(image, 0, 0);
      return context.getImageData(0, 0, image.width, image.height);
    };
    const [withCard, without] = [await load(a), await load(b)];
    const scale = withCard.width / innerWidth;
    // Inside the card, inset 8 px so the rounded corners (14 px radius), the shadow and the edge never count.
    const left = Math.round((box.left + 8) * scale), top = Math.round((box.top + 8) * scale);
    const w = Math.round((box.width - 16) * scale), h = Math.round((box.height - 16) * scale);
    const luminance = (image: ImageData): Float32Array => {
      const out = new Float32Array(w * h);
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const i = ((top + y) * image.width + left + x) * 4;
        out[y * w + x] = 0.2126 * image.data[i]! + 0.7152 * image.data[i + 1]! + 0.0722 * image.data[i + 2]!;
      }
      return out;
    };
    // The picture minus its own box blur (radius about 2 CSS px), through an integral image: strokes stay, soft shapes go.
    const highPass = (values: Float32Array): Float32Array => {
      const radius = Math.max(2, Math.round(2 * scale));
      const integral = new Float64Array((w + 1) * (h + 1));
      for (let y = 0; y < h; y++) {
        let row = 0;
        for (let x = 0; x < w; x++) { row += values[y * w + x]!; integral[(y + 1) * (w + 1) + x + 1] = integral[y * (w + 1) + x + 1]! + row; }
      }
      const out = new Float32Array(w * h);
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const x0 = Math.max(0, x - radius), x1 = Math.min(w, x + radius + 1), y0 = Math.max(0, y - radius), y1 = Math.min(h, y + radius + 1);
        const sum = integral[y1 * (w + 1) + x1]! - integral[y0 * (w + 1) + x1]! - integral[y1 * (w + 1) + x0]! + integral[y0 * (w + 1) + x0]!;
        out[y * w + x] = values[y * w + x]! - sum / ((x1 - x0) * (y1 - y0));
      }
      return out;
    };
    const hpA = highPass(luminance(withCard)), hpB = highPass(luminance(without));
    const counted = new Uint8Array(w * h).fill(1);
    for (const rect of own) {
      const x0 = Math.max(0, Math.round((rect.left - 4) * scale) - left), x1 = Math.min(w, Math.round((rect.right + 4) * scale) - left);
      const y0 = Math.max(0, Math.round((rect.top - 4) * scale) - top), y1 = Math.min(h, Math.round((rect.bottom + 4) * scale) - top);
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) counted[y * w + x] = 0;
    }
    let saa = 0, sbb = 0, sab = 0, n = 0;
    for (let i = 0; i < w * h; i++) {
      if (!counted[i]) continue;
      n++; saa += hpA[i]! * hpA[i]!; sbb += hpB[i]! * hpB[i]!; sab += hpA[i]! * hpB[i]!;
    }
    return { corr: saa > 0 && sbb > 0 ? sab / Math.sqrt(saa * sbb) : 0, behindRms: Math.sqrt(sbb / Math.max(1, n)), shownRms: Math.sqrt(saa / Math.max(1, n)), pixels: n };
  }, { a: withCard.toString("base64"), b: withoutCard.toString("base64") });
}
