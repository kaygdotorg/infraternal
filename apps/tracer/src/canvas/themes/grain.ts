// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Film grain for the window surfaces (D341, #323). The owner: "grain should be applied to the window, not the background", and
 * "how much is 100% grain btw? it looks too much, can our slider be tamed a little like we did with blur 0 being 0 and 100% being 24px?"
 *
 * A grain is one small tile of noise laid over a surface as a second background image, so it is part of the surface: under the text, under the
 * content, on exactly the pixels of the window or the floating card, and it moves, blurs and clips with it. The tile is white and black specks of
 * random strength (alpha), so it neither lightens nor darkens the surface on average; it only adds texture. Nothing animates (reduced motion has
 * nothing to stop), the tile is one image the compositor draws as part of the surface, and no script runs per frame.
 *
 * **The scale.** The slider is 0 to 100% and linear: the strongest speck of the tile has an alpha of `amount x GRAIN_MAX`, so the grain's strength (the RMS change
 * it makes to a surface's pixels) grows in a straight line from nothing to its largest. `themes-grain.spec.ts` measures it on the real page and prints it
 * (`GRAINSCALE ...`), against two references on the same window colour: the product's own mesh grain (its tile at 0.035 opacity blended with `overlay`, about half a
 * level of 255) and the grain round 3 shipped (the same tile at 0.4 opacity: about 7 levels on a dark window, which the owner found too much). A `GRAIN_MAX` of 0.08
 * measured the same strength as round 3 (about 7 levels), so it was not tamed; 0.04 is half of that: about 3.5 levels at 100%, clearly visible and not loud. The
 * amount is baked into the tile (a different tile for each whole percent, made once and kept), because a background layer has no opacity of its own.
 */
export const GRAIN_MAX = 0.04;
const made = new Map<number, string>();

/** A CSS image for an amount of grain, 0 to 100: "none" for none, else a data URL of a 128 px tile. The same amount gives the same tile. */
export function grainImage(amount: number): string {
  const percent = Math.max(0, Math.min(100, Math.round(amount)));
  if (percent === 0) return "none";
  const kept = made.get(percent);
  if (kept) return kept;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 128;
  const context = canvas.getContext("2d");
  if (!context) return "none";
  const image = context.createImageData(128, 128);
  // A fixed seed, so the grain of an amount is the same picture every time (a screenshot is repeatable).
  let seed = 0x9e3779b9;
  const random = (): number => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 4294967296; };
  for (let i = 0; i < image.data.length; i += 4) {
    const speck = random() > 0.5 ? 255 : 0;
    image.data[i] = image.data[i + 1] = image.data[i + 2] = speck;
    image.data[i + 3] = Math.round(255 * (percent / 100) * GRAIN_MAX * random());
  }
  context.putImageData(image, 0, 0);
  const url = `url("${canvas.toDataURL("image/png")}")`;
  made.set(percent, url);
  return url;
}
