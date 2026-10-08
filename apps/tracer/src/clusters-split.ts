/**
 * The droplet split (TASTE section 3: a window divides like a water droplet; stretch, neck,
 * separate, with a bouncy and sticky spring).
 *
 * The caller has already put the two windows in their final places (A above B in one column).
 * This module plays the way there with one spring `p`: 1 is "still one window", 0 is "two
 * windows at rest".
 *
 * - Stretch: at p = 1 A is scaled about its top edge, and B about its bottom edge, so together
 *   they cover exactly the footprint the single window had.
 * - Neck: as p falls the two shrink apart. A bridge between them (same fill and hairline as a
 *   window) thins as the gap opens and is gone before the windows are fully apart.
 * - Separate and bounce: the spring undershoots, so for a moment each half is smaller than its
 *   slot and the gap is wide, then they settle. Reduced motion only fades B in.
 *
 * Only transform and opacity change, and everything is cleared at rest so settled text never
 * sits on a transformed layer.
 */
import { Spring } from "../../../packages/ui/src/spring";

const clamp = (v: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, v));

export function dropletSplit(a: HTMLElement, b: HTMLElement): Promise<void> {
  return new Promise((resolve) => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      b.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" }).onfinish = () => resolve();
      return;
    }
    const column = a.parentElement!;
    const hA = a.offsetHeight, hB = b.offsetHeight;
    const gap = Math.max(1, b.offsetTop - (a.offsetTop + hA));
    const stretch = (hA + gap + hB) / hA; // the single window's footprint, as a scale of A
    const neck = document.createElement("div");
    neck.className = "cl-neck";
    neck.style.cssText = `top:${a.offsetTop + hA}px;left:${a.offsetLeft}px;width:${a.offsetWidth}px;height:${gap}px`;
    column.append(neck);
    a.style.transformOrigin = "50% 0";
    b.style.transformOrigin = "50% 100%";
    a.style.zIndex = "1";
    const inner = [a, b].flatMap((w) => [...w.querySelectorAll<HTMLElement>(":scope > .ui-window-head, :scope > .ui-window-body")]);
    for (const part of inner) part.style.transformOrigin = "0 0";
    const draw = (p: number): void => {
      const sa = 1 + (stretch - 1) * p;
      // A touch of waist while it stretches: narrower when most stretched.
      const sx = 1 - 0.035 * clamp(p, 0, 1);
      a.style.transform = `scale(${sx}, ${sa})`;
      b.style.transform = `scale(${sx}, ${sa})`;
      // Only the frame stretches; the header and text are counter-scaled so they keep their shape.
      for (const part of inner) part.style.transform = `scale(${1 / sx}, ${1 / sa})`;
      b.style.opacity = String(clamp((0.62 - p) / 0.2, 0, 1));
      // Visual gap between the two halves.
      const gapNow = (b.offsetTop + hB - hB * sa) - (a.offsetTop + hA * sa);
      const thin = clamp(1 - gapNow / (hA * 0.45), 0, 1);
      neck.style.opacity = gapNow > 2 && thin > 0.02 ? "1" : "0";
      neck.style.transform = `scale(${(0.04 + 0.5 * thin).toFixed(3)}, ${Math.max(0.01, gapNow / gap).toFixed(3)})`;
    };
    const spring = new Spring(1, (p) => {
      if (p === 0) {
        for (const el of [a, b, ...inner]) { el.style.transform = ""; el.style.transformOrigin = ""; el.style.opacity = ""; el.style.zIndex = ""; }
        neck.remove();
        resolve();
        return;
      }
      draw(p);
    }, { visualDuration: 0.62, bounce: 0.42 });
    requestAnimationFrame(() => spring.set(0));
  });
}
