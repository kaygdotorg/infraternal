/**
 * The motion curve of the product for TypeScript (D372, #345).
 *
 * CSS reads the curve as `var(--ease-out)`; the Web Animations API cannot, so `element.animate` calls import it from here.
 */

/** The ease-out curve as a string for an `easing` option. It must stay equal to `--ease-out` in packages/ui/styles.css; change both together, or neither. */
export const EASE_OUT = "cubic-bezier(0.23, 1, 0.32, 1)";
