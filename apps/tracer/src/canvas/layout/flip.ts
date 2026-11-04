/**
 * FLIP reflows: when a layout changes (a window opens, closes, moves, a column resizes), every element that
 * moved animates from where it was to where it is with the spring's curve. Only `transform` is animated, in world
 * units (the camera zoom is divided out), and as a Web Animation: the browser runs it on the compositor, so a reflow
 * costs the main thread nothing per frame (a per-frame style write per element was 80-100 ms of Layerize and Commit for
 * one close). The spring is sampled once per configuration into a `linear()` easing that settles like the spring
 * does: critically damped, no value passes its end (TASTE §3, no overshoot). The caller measures first, changes the
 * layout, then plays; a new measure of an element that is still animating cancels it so the "first" position is always the true one. Reduced motion skips the animation.
 */
import type { SpringConfig } from "../../../../../packages/ui/src/spring";

/** The duration-based spring config: critically damped, so it has no bounce to set. */
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

/** A spring's progress from 1 (where the element was) to 0 (where it is), sampled into a CSS easing. */
const easings = new Map<string, { css: string; duration: number }>();
/**
 * Samples a critically damped spring into a CSS `linear()` easing and its duration in milliseconds. It runs from 0 to 1, never goes past
 * 1, and ends where the spring comes to rest (at most 3 seconds). The result is cached for each duration.
 */
export function springEasing(cfg: FlipSpring): { css: string; duration: number } {
  const key = String(cfg.visualDuration);
  const hit = easings.get(key);
  if (hit) return hit;
  // The same physics as `Spring`: omega from the visual duration, damping ratio 1.
  const omega = (2 * Math.PI) / (cfg.visualDuration * 1.2), k = omega * omega, c = 2 * omega;
  const h = 1 / 240, every = 4; // a sample every 1/60 s
  let x = 1, v = 0, t = 0;
  const points = [0];
  while (t < 3) {
    for (let i = 0; i < every; i++) { v += (-k * x - c * v) * h; x += v * h; t += h; }
    points.push(Math.min(1, 1 - x)); // the explicit Euler steps must not nudge a sample past the end
    if (Math.abs(x) < 0.0005 && Math.abs(v) < 0.03) break;
  }
  points[points.length - 1] = 1;
  const out = { css: `linear(${points.map((p) => p.toFixed(4)).join(", ")})`, duration: Math.round(t * 1000) };
  easings.set(key, out);
  return out;
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
    play(first, scale = false, cfg = { visualDuration: 0.5 }) {
      if (reduced.matches) return;
      const z = zoom();
      const { css, duration } = springEasing(cfg);
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
