/** Pure frame shaping for remote app-window dimensions, kept with the on-demand app-window feature. */
export interface ShapeBox {
  width: number;
  height: number;
  chromeWidth: number;
  chromeHeight: number;
  minWidth: number;
  maxWidth: number;
  minHeight: number;
  maxHeight: number;
}

/** Keeps the picture at its remote aspect ratio while respecting the canvas window's frame and limits. */
export function shapeFor(box: ShapeBox, aspect: number): { width: number; height: number } {
  const same = { width: box.width, height: box.height };
  if (!(aspect > 0) || !Number.isFinite(aspect)) return same;
  const clamp = (v: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, v));
  let height = box.height;
  let width = (height - box.chromeHeight) * aspect + box.chromeWidth;
  if (width > box.maxWidth || width < box.minWidth) {
    width = clamp(width, box.minWidth, box.maxWidth);
    height = clamp((width - box.chromeWidth) / aspect + box.chromeHeight, box.minHeight, box.maxHeight);
  }
  width = Math.round(width); height = Math.round(height);
  return Math.abs(width - box.width) <= 1 && Math.abs(height - box.height) <= 1 ? same : { width, height };
}
