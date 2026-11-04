/**
 * The size a stream is asked for (D208 A2, D200 V3): the window's own box times the viewer's pixel density, so the
 * picture is one to one with the screen it lands on and needs no scaling. The wire bounds it (contracts/wire.md §9):
 * even sides of 2 to 4096, at most four megapixels, density 1 to 4 and a point size that matches the pixels within one.
 *
 * A box that would exceed the bounds lowers the density first (a sharp picture at 1× beats a refused stream), then the
 * box itself, so the request is always one the machine accepts. Pure: unit-tested in `size.test.ts`.
 */

/** A stream size the machine will accept: even pixel sides, the matching box in points, and the density between them. */
export interface StreamSize {
  /** Pixels of the picture (even). */
  width: number;
  height: number;
  /** The box in points on the machine, and the density that relates it to the pixels. */
  canvasWidth: number;
  canvasHeight: number;
  backingScale: number;
}

/** Largest picture side the wire allows, in pixels. */
const MAX_SIDE = 4096;
/** Largest picture the wire allows, in total pixels (four megapixels). */
const MAX_PIXELS = 4 * 1024 * 1024;
/** Smallest picture side the wire allows, in pixels. */
const MIN_SIDE = 2;

/** Rounds down to an even number, never below `MIN_SIDE`. */
const evenFloor = (v: number): number => Math.max(MIN_SIDE, Math.floor(v / 2) * 2);

/**
 * `cssWidth` and `cssHeight` are the window body's layout size (the camera's zoom is not part of it: zooming the
 * canvas scales the picture, it does not ask the machine for more pixels).
 */
export function chooseSize(cssWidth: number, cssHeight: number, density: number): StreamSize {
  const w = Math.max(MIN_SIDE, cssWidth), h = Math.max(MIN_SIDE, cssHeight);
  let scale = Math.min(4, Math.max(1, density));
  // Lower the density until the pixels fit the bounds, never below 1.
  scale = Math.min(scale, MAX_SIDE / w, MAX_SIDE / h, Math.sqrt(MAX_PIXELS / (w * h)));
  scale = Math.max(1, Math.round(scale * 1000) / 1000);
  let canvasWidth = w, canvasHeight = h;
  // Still too big at 1×: the box itself shrinks to the bound (the window is then larger than its picture's cap).
  if (canvasWidth * scale > MAX_SIDE) canvasWidth = MAX_SIDE / scale;
  if (canvasHeight * scale > MAX_SIDE) canvasHeight = MAX_SIDE / scale;
  if (canvasWidth * canvasHeight * scale * scale > MAX_PIXELS) {
    const k = Math.sqrt(MAX_PIXELS / (canvasWidth * canvasHeight * scale * scale));
    canvasWidth *= k; canvasHeight *= k;
  }
  let width = evenFloor(canvasWidth * scale), height = evenFloor(canvasHeight * scale);
  // The machine checks that points times density equals the pixels within one pixel; flooring to even keeps it.
  canvasWidth = width / scale; canvasHeight = height / scale;
  width = Math.min(width, MAX_SIDE); height = Math.min(height, MAX_SIDE);
  return { width, height, canvasWidth: Math.round(canvasWidth * 100) / 100, canvasHeight: Math.round(canvasHeight * 100) / 100, backingScale: scale };
}

/** The wire's `density_milli` for a size. */
export const densityMilli = (size: StreamSize): number => Math.min(4000, Math.max(1000, Math.round(size.backingScale * 1000)));

/** Whether a newer size is worth sending: a change of at least two pixels on a side (rounding noise is not a resize). */
export function sizeChanged(a: StreamSize | undefined, b: StreamSize): boolean {
  return !a || Math.abs(a.width - b.width) >= 2 || Math.abs(a.height - b.height) >= 2 || a.backingScale !== b.backingScale;
}
