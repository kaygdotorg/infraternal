/**
 * What the canvas holds in memory, and what it gives back (a phone restores a page with a small budget, and iOS
 * ends a page that keeps too much while the phone is locked).
 *
 * - Views far from the screen are not painted: `visibility: hidden` frees their compositor layers and paint work.
 *   "Far" is more than one screen from the visible area, so a view that is flown to is already painted when it
 *   arrives. Layout is untouched. Every window of a far view is told `setVisible(false)` (a live renderer then
 *   releases its canvas), and `setVisible(true)` when the view is near again.
 * - A hidden page (`visibilitychange`, `pagehide`) ends a split in progress (and with it its GL context),
 *   releases the dot layers and the compositor hint on the world, hides the world (which drops every layer under
 *   it) and tells every window it is not visible. `pageshow` and visible draw it all again.
 * - Windows more than a screen away from the visible area are parked (`data-parked`: `visibility: hidden`, layout
 *   untouched). Every painted window is paint chunks the compositor walks again on every frame the camera moves (about
 *   0.07 ms of layerizing per window, so 55 windows are about 4 ms of every pan, zoom and flight frame, measured at
 *   DPR 2); a parked one is nothing. The active window is never parked, so focus and the keyboard still reach it.
 * - Nothing here runs per frame except one rectangle test per view while the camera moves.
 */
import type { Ctx, ViewRec } from "./context";
import { boxOf } from "./layout/geometry";
import { endSplit } from "./layout/droplet-handle";
import type { Backdrop } from "./backdrop";

/** What the canvas does to hold less memory: culling far views, marking windows on screen, and reacting to a hidden page. */
export interface Memory {
  /** Culls views by the camera's visible area; cheap enough for every frame. */
  cull(): void;
  /** Marks a window `data-onscreen` while it intersects the canvas (Frosted windows blur only those). Returns the stop. */
  watch(window: HTMLElement): () => void;
  /** Stops the observers and any pending frame. */
  dispose(): void;
}

/**
 * Makes the memory manager for the canvas `cx`. `backdrop` (optional) is released when the page is hidden. The rules (far views are not painted,
 * windows a screen away are parked, a hidden page gives everything back) are described in the module comment. Listeners end when
 * the canvas's abort signal fires.
 */
export function createMemory(cx: Ctx, backdrop: Backdrop | undefined): Memory {
  const { world, camera, views, signal } = cx;
  const far = new WeakSet<ViewRec>();
  let hidden = false;

  // How live a window is (near the screen, level of detail) is decided in windows/visibility.ts; this module only
  // says which views are far and when the page is paused, and that module combines the three.
  const setVisible = (c: ViewRec, visible: boolean): void => cx.visibility.setViewFar(c, !visible);

  const cull = (): void => {
    if (hidden || !camera.vw || !camera.vh) return;
    const { tx, ty, vw, vh } = camera, z = camera.cam.z;
    const x0 = -tx / z - vw / z, x1 = (-tx + 2 * vw) / z, y0 = -ty / z - vh / z, y1 = (-ty + 2 * vh) / z;
    for (const c of views.values()) {
      const box = boxOf(c.view, cx.state.metrics);
      const isFar = c.x + box.w < x0 || c.x > x1 || c.y + box.h < y0 || c.y > y1;
      if (isFar === far.has(c)) continue;
      if (isFar) far.add(c); else far.delete(c);
      c.el.style.visibility = isFar ? "hidden" : "";
      setVisible(c, !isFar);
    }
  };

  const hide = (): void => {
    hidden = true;
    endSplit();
    backdrop?.release();
    world.style.willChange = "";
    world.style.visibility = "hidden"; // every layer under the world goes with it
    cx.visibility.setPaused(true);
  };
  const show = (): void => {
    if (document.hidden || !hidden) return;
    hidden = false;
    world.style.visibility = "";
    camera.apply(true);
    cx.visibility.setPaused(false);
    cull();
  };
  document.addEventListener("visibilitychange", () => { if (document.hidden) hide(); else show(); }, { signal });
  window.addEventListener("pagehide", hide, { signal });
  window.addEventListener("pageshow", show, { signal });

  // Frosted windows blur what is behind them, and only while they are on screen: an observer flips an attribute when a
  // window crosses the canvas edge (never per frame). A window that is really on screen is never parked.
  const unpark = (w: HTMLElement): void => { pending.delete(w); w.removeAttribute("data-parked"); };
  const onscreen = new IntersectionObserver((entries) => {
    for (const e of entries) {
      const w = e.target as HTMLElement;
      w.toggleAttribute("data-onscreen", e.isIntersecting);
      if (e.isIntersecting && w.hasAttribute("data-parked")) unpark(w);
    }
  }, { root: cx.viewport });
  signal.addEventListener("abort", () => onscreen.disconnect());
  // Windows a screen or more away are parked. Parking is at once; un-parking (a style recalculation of the window and a
  // paint, about 1.5 ms each) is spread over frames, two a frame, because a column of eight windows entering the margin
  // together was a 10-20 ms frame in the middle of a zoom or a pan. The margin is wide enough (1.5 screens) that they are
  // un-parked well before they can be seen; a window that is seen is un-parked by the observer above at once.
  const pending = new Set<HTMLElement>();
  let drainFrame = 0;
  const drain = (): void => {
    drainFrame = 0;
    let n = 0;
    for (const w of pending) { unpark(w); if (++n === 2) break; }
    if (pending.size) drainFrame = requestAnimationFrame(drain);
  };
  const parked = new IntersectionObserver((entries) => {
    for (const e of entries) {
      const w = e.target as HTMLElement;
      if (!e.isIntersecting) { pending.delete(w); w.setAttribute("data-parked", ""); }
      else if (w.hasAttribute("data-parked")) pending.add(w);
    }
    if (pending.size && !drainFrame) drainFrame = requestAnimationFrame(drain);
  }, { root: cx.viewport, rootMargin: "150% 150% 150% 150%" });
  signal.addEventListener("abort", () => { parked.disconnect(); cancelAnimationFrame(drainFrame); });

  return {
    cull,
    watch(window) { onscreen.observe(window); parked.observe(window); return () => { onscreen.unobserve(window); parked.unobserve(window); pending.delete(window); }; },
    dispose() { onscreen.disconnect(); parked.disconnect(); cancelAnimationFrame(drainFrame); },
  };
}
