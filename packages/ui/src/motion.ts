/**
 * The product's motion curve for TypeScript (D372, #345).
 *
 * CSS reads the curve as `var(--ease-out)` (packages/ui/styles.css). The Web Animations API cannot: an `easing` option is a
 * plain string, so every `element.animate(...)` call imports this constant instead of pasting the curve. It must stay equal to
 * `--ease-out`; change both together, or neither.
 */
export const EASE_OUT = "cubic-bezier(0.23, 1, 0.32, 1)";
