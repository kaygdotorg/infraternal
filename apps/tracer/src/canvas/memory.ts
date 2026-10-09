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
 * - Nothing here runs per frame except one rectangle test per view while the camera moves.
 */
import type { Ctx, ViewRec } from "./context";
import { boxOf } from "./layout/geometry";
import { endSplit } from "./layout/droplet-handle";
import type { Backdrop } from "./backdrop";

export interface Memory {
  /** Culls views by the camera's visible area; cheap enough for every frame. */
  cull(): void;
  /** Marks a window `data-onscreen` while it intersects the canvas (Frosted windows blur only those). Returns the stop. */
  watch(window: HTMLElement): () => void;
  dispose(): void;
}

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
  // window crosses the canvas edge (never per frame).
  const onscreen = new IntersectionObserver((entries) => { for (const e of entries) (e.target as HTMLElement).toggleAttribute("data-onscreen", e.isIntersecting); }, { root: cx.viewport });
  signal.addEventListener("abort", () => onscreen.disconnect());

  return {
    cull,
    watch(window) { onscreen.observe(window); return () => onscreen.unobserve(window); },
    dispose() { onscreen.disconnect(); },
  };
}
