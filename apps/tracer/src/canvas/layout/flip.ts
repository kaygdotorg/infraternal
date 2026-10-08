/**
 * FLIP reflows: when a layout changes (a window opens, closes, moves, a column resizes), every element that
 * moved animates from where it was to where it is, on one spring per element. The caller measures first,
 * changes the layout, then plays. Only `transform` is animated, in world units (the camera zoom is divided
 * out), and a new measure of an element that is still animating jumps it to rest first so the "first"
 * position is always the true one. Reduced motion skips the animation.
 */
import { Spring } from "../../../../../packages/ui/src/spring";

export interface Flip {
  /** Records where the elements are now. */
  measure(nodes: Iterable<HTMLElement>): Map<HTMLElement, DOMRect>;
  /** Animates every element of `first` from its recorded box to its current one. `scale` also animates size. */
  play(first: Map<HTMLElement, DOMRect>, scale?: boolean, cfg?: { visualDuration: number; bounce: number }): void;
  /** The elements of a view that take part in a reflow. */
  targets(colsEl: HTMLElement): HTMLElement[];
}

export function createFlip(zoom: () => number, invalidate: () => void): Flip {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const springs = new WeakMap<HTMLElement, Spring>();
  return {
    measure(nodes) {
      const out = new Map<HTMLElement, DOMRect>();
      for (const n of nodes) {
        out.set(n, n.getBoundingClientRect());
        springs.get(n)?.set(0, true);
      }
      return out;
    },
    play(first, scale = false, cfg = { visualDuration: 0.5, bounce: 0.22 }) {
      if (reduced.matches) return;
      const z = zoom();
      for (const [n, a] of first) {
        if (!n.isConnected) continue;
        const b = n.getBoundingClientRect();
        const dx = (a.left - b.left) / z, dy = (a.top - b.top) / z;
        const sw = scale && b.width ? a.width / b.width : 1, sh = scale && b.height ? a.height / b.height : 1;
        if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5 && Math.abs(sw - 1) < 0.01 && Math.abs(sh - 1) < 0.01) continue;
        n.style.transformOrigin = "0 0";
        const spring = new Spring(1, (p) => {
          if (p === 0) { n.style.transform = ""; n.style.transformOrigin = ""; invalidate(); return; }
          n.style.transform = `translate(${dx * p}px, ${dy * p}px)${scale ? ` scale(${1 + (sw - 1) * p}, ${1 + (sh - 1) * p})` : ""}`;
          invalidate();
        }, cfg);
        springs.set(n, spring);
        spring.set(0);
      }
    },
    targets: (colsEl) => [...colsEl.querySelectorAll<HTMLElement>(".ui-window, .cl-slot, .cl-col")],
  };
}
