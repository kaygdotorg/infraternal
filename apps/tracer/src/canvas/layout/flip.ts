/**
 * FLIP reflows: when a layout changes (a window opens, closes, moves, a column resizes), every element that
 * moved animates from where it was to where it is on the product's ease-out curve. Only `transform` is animated, in world
 * units (the camera zoom is divided out), and as a Web Animation: the browser runs it on the compositor, so a reflow
 * costs the main thread nothing per frame (a per-frame style write per element was 80-100 ms of Layerize and Commit for
 * one close). The curve is `EASE_OUT`, the same one `Spring.set` plays, so
 * a reflow and the canvas motion beside it move alike; no value passes its end (TASTE §3, no overshoot). The caller measures first, changes the
 * layout, then plays; a new measure of an element that is still animating cancels it so the "first" position is always the true one. Reduced motion skips the animation.
 */
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import type { SpringConfig } from "../../../../../packages/ui/src/spring";

/** The duration-based spring config: a reflow plays the ease-out curve for its `visualDuration`. */
type FlipSpring = Extract<SpringConfig, { visualDuration: number }>;

/** The reflow animator made by `createFlip`: call `measure`, change the layout, then `play`. */
export interface Flip {
  /** Records where the elements are now. */
  measure(nodes: Iterable<HTMLElement>): Map<HTMLElement, DOMRect>;
  /** Animates every element of `first` from its recorded box to its current one. `scale` also animates size. */
  play(first: Map<HTMLElement, DOMRect>, scale?: boolean, cfg?: FlipSpring): void;
  /** The elements of a view that take part in a reflow. */
  targets(colsEl: HTMLElement): HTMLElement[];
}

/**
 * The easing and length in milliseconds of a reflow: the product's ease-out curve (`EASE_OUT`, the same curve as
 * `Spring.set` and CSS `var(--ease-out)`) for exactly the visual duration. It covers most of the distance in the first
 * frames and never passes its end (TASTE section 3, "Fast, ease-out, under 300 ms" and "No overshoot, ever"). A
 * sampled spring curve was used before #471; it started at zero speed and settled at 1.3x its duration.
 */
export function flipEasing(cfg: FlipSpring): { css: string; duration: number } {
  return { css: EASE_OUT, duration: Math.round(cfg.visualDuration * 1000) };
}

/**
 * `tick` runs once per frame while any reflow animation plays: the canvas redraws what follows the windows (arrows and
 * ports) from it. It must not write styles of the moving elements.
 */
export function createFlip(zoom: () => number, tick: () => void): Flip {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const running = new Map<HTMLElement, Animation>();
  let raf = 0;
  const loop = (): void => { raf = running.size ? requestAnimationFrame(loop) : 0; if (running.size) tick(); };
  return {
    measure(nodes) {
      const out = new Map<HTMLElement, DOMRect>();
      for (const n of nodes) {
        out.set(n, n.getBoundingClientRect());
        running.get(n)?.cancel();
      }
      return out;
    },
    play(first, scale = false, cfg = { visualDuration: 0.28 }) {
      if (reduced.matches) return;
      const z = zoom();
      const { css, duration } = flipEasing(cfg);
      for (const [n, a] of first) {
        if (!n.isConnected) continue;
        // An element with no box before the change (a column of a group, which has none of its own) has no place to
        // animate from: animating it from the origin is what made a dissolved group's columns jump across the view.
        if (a.width === 0 && a.height === 0) continue;
        const b = n.getBoundingClientRect();
        const dx = (a.left - b.left) / z, dy = (a.top - b.top) / z;
        const sw = scale && b.width ? a.width / b.width : 1, sh = scale && b.height ? a.height / b.height : 1;
        if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5 && Math.abs(sw - 1) < 0.01 && Math.abs(sh - 1) < 0.01) continue;
        n.style.transformOrigin = "0 0";
        const from = `translate(${dx}px, ${dy}px)${scale ? ` scale(${sw}, ${sh})` : ""}`;
        const to = `translate(0px, 0px)${scale ? " scale(1, 1)" : ""}`;
        running.get(n)?.cancel();
        const anim = n.animate([{ transform: from }, { transform: to }], { duration, easing: css });
        running.set(n, anim);
        const done = (): void => {
          if (running.get(n) !== anim) return; // replaced by a newer reflow: it owns the origin now
          running.delete(n);
          n.style.transformOrigin = "";
          tick();
        };
        anim.onfinish = done;
        anim.oncancel = done;
      }
      if (running.size && !raf) raf = requestAnimationFrame(loop);
    },
    targets: (colsEl) => [...colsEl.querySelectorAll<HTMLElement>(".ui-window, .cl-slot, .cl-col, .cl-group")],
  };
}
