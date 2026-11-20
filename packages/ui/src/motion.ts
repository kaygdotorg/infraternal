/**
 * The motion curve of the product for TypeScript (D372, #345).
 *
 * CSS reads the curve as `var(--ease-out)`; the Web Animations API cannot, so `element.animate` calls import it from here.
 */

/** The ease-out curve as a string for an `easing` option. It must stay equal to `--ease-out` in packages/ui/styles.css; change both together, or neither. */
export const EASE_OUT = "cubic-bezier(0.23, 1, 0.32, 1)";

/** The control points of {@link EASE_OUT}: x1, y1, x2, y2. */
const [X1, Y1, X2, Y2] = [0.23, 1, 0.32, 1];
/** The x of the curve at its parameter `s` (a cubic Bézier from (0, 0) to (1, 1)). */
const bezierX = (s: number): number => 3 * X1 * s * (1 - s) ** 2 + 3 * X2 * s * s * (1 - s) + s ** 3;
/** The y of the curve at its parameter `s`. */
const bezierY = (s: number): number => 3 * Y1 * s * (1 - s) ** 2 + 3 * Y2 * s * s * (1 - s) + s ** 3;

/**
 * The product's ease-out curve as a function, for motion that runs per frame in script (`Spring.set`): `progress` is
 * the share of the duration that has passed (0 to 1), and the result is the share of the distance covered. It is the
 * same curve CSS draws for `var(--ease-out)`, so a canvas motion and a CSS transition of the same length move alike.
 * Most of the distance is covered at once (a quarter of it in the first frame of a 280 ms move), then it glides in.
 * The value never leaves [0, 1], so nothing driven by it can overshoot (TASTE §3).
 *
 * The curve's x is monotonic, so a bisection on it is exact to 2^-24 in 24 steps; that is cheaper than one style write.
 */
export function easeOut(progress: number): number {
  if (progress <= 0) return 0;
  if (progress >= 1) return 1;
  let lo = 0, hi = 1;
  for (let i = 0; i < 24; i++) {
    const mid = (lo + hi) / 2;
    if (bezierX(mid) < progress) lo = mid; else hi = mid;
  }
  return bezierY((lo + hi) / 2);
}
