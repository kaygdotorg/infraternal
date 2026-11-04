/**
 * Glitch text (#21): two offset copies of the text, clipped to shifting horizontal
 * bands, over the original.
 *
 * Design choices:
 * - Monochrome by default (white and grey offsets), matching the black-and-white
 *   onboarding; pass `colors` for the classic red/cyan.
 * - It plays for a moment and then settles into clean text (`settleAfter`), instead of
 *   looping forever: a welcome is a moment, and an endless clip-path animation costs
 *   paint every frame for nothing (DECISIONS 81).
 * - Reduced motion: no glitch at all, just the text.
 */
/**
 * Options for {@link glitchText}.
 * - `speed`: seconds scale of the animation (default 0.5); the two copies run at 3x and 2x of it.
 * - `settleAfter`: milliseconds until the effect stops and the text is clean; the effect runs until `destroy()` when omitted.
 * - `colors`: the two offset copy colours (any CSS colour), default white and grey.
 */
export interface GlitchOptions { speed?: number; settleAfter?: number; colors?: [string, string] }

/**
 * Makes `el` show `text` with the glitch effect. Needs the `.glitch` styles from `packages/ui/styles.css`.
 * Under reduced motion it shows clean text at once. Returns a handle: `destroy()` settles the text and cancels the timer.
 */
export function glitchText(el: HTMLElement, text: string, o: GlitchOptions = {}): { destroy(): void } {
  const speed = o.speed ?? 0.5;
  const [a, b] = o.colors ?? ["rgb(255 255 255 / 0.55)", "rgb(150 150 160 / 0.6)"];
  el.classList.add("glitch");
  el.dataset.text = text;
  el.textContent = text;
  el.style.setProperty("--g-after-dur", `${speed * 3}s`);
  el.style.setProperty("--g-before-dur", `${speed * 2}s`);
  el.style.setProperty("--g-after-shadow", `-4px 0 ${a}`);
  el.style.setProperty("--g-before-shadow", `4px 0 ${b}`);
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) { el.classList.add("is-settled"); return { destroy() {} }; }
  const timer = o.settleAfter === undefined ? 0 : window.setTimeout(() => el.classList.add("is-settled"), o.settleAfter);
  return { destroy() { clearTimeout(timer); el.classList.add("is-settled"); } };
}
