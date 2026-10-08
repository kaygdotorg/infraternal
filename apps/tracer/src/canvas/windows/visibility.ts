/**
 * Which windows are live. A window is live when it is near the screen and the camera is at a live level of
 * detail; everything else (another view, far off screen, a thumbnail) is told so, and its session binding stops
 * drawing and gives its canvas backing store back (D183, and the iOS memory rule: about one screen of pixels).
 *
 * It costs nothing while still: one IntersectionObserver (it reports changes only) and the camera's level of
 * detail hook; no per-frame work and no timers.
 */
import type { Ctx, ViewRec, WinRec } from "../context";

export interface Visibility {
  watch(rec: WinRec): void;
  unwatch(rec: WinRec): void;
  /** A view is far from the screen (or near again): its windows are not live while it is far. */
  setViewFar(view: ViewRec, far: boolean): void;
  /** The page is hidden or frozen: no window is live until it is shown again. */
  setPaused(paused: boolean): void;
  /** The level of detail changed. */
  lodChanged(): void;
  dispose(): void;
}

export function createVisibility(cx: Ctx): Visibility {
  const near = new Set<Element>();
  const recs = new Map<Element, WinRec>();
  const farViews = new WeakSet<ViewRec>();
  let paused = false;
  const apply = (rec: WinRec): void => {
    rec.binding?.setVisible(!paused && !farViews.has(rec.owner) && near.has(rec.card.root) && cx.camera.lod === "live");
  };
  // A margin of half a viewport keeps the neighbours that peek in at the edge alive.
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) near.add(e.target); else near.delete(e.target);
      const rec = recs.get(e.target);
      if (rec) apply(rec);
    }
  }, { root: cx.viewport, rootMargin: "50% 50% 50% 50%" });
  return {
    watch(rec) { recs.set(rec.card.root, rec); io.observe(rec.card.root); },
    unwatch(rec) { io.unobserve(rec.card.root); recs.delete(rec.card.root); near.delete(rec.card.root); },
    setViewFar(view, far) { if (far) farViews.add(view); else farViews.delete(view); for (const rec of view.wins.values()) apply(rec); },
    setPaused(value) { paused = value; for (const rec of recs.values()) apply(rec); },
    lodChanged() { for (const rec of recs.values()) apply(rec); },
    dispose() { io.disconnect(); recs.clear(); near.clear(); },
  };
}
