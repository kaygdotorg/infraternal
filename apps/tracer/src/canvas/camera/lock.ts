/**
 * Navigation: the canvas lock, the stops it rests on, and every way the camera is sent somewhere (D177).
 *
 * Locked (the default, re-enabled on every view switch or fly-to), the camera is fixed to the current view at the
 * zoom where the view is as tall as the viewport and rests only on a stop: one per column. Horizontal gestures
 * move between stops, vertical ones between the windows of a column. No zoom, no free pan. Unlocked, the canvas
 * is free (pan, zoom, thumbnails); unlocking never moves the camera, and the overview is its own action.
 *
 * This module owns `currentView`, `canvasLock` and `snapIdx` (on the shared state), and tells listeners when the
 * lock changes so the buttons and the toolbar row can repaint.
 */
import type { Ctx, ViewRec, WinRec } from "../context";
import type { ViewId } from "../model/types";
import { COLUMN_GAP, type Rect } from "../layout/geometry";
import { scrollToWindow } from "../layout/columns";
import { nearestStop as nearest, stopsFor as stops, type Stops } from "../layout/stops";
import { bounds, clamp, type Cam } from "./camera";

export interface Nav {
  stopsFor(c: ViewRec): Stops;
  nearestStop(c: ViewRec, cx: number): number;
  goStop(c: ViewRec, i: number, instant?: boolean): void;
  /** Sets the lock and repaints; does not move the camera. */
  applyCanvasLock(on: boolean): void;
  /** Sets the lock; turning it on snaps to the nearest stop of the current view. */
  setCanvasLock(on: boolean, instant?: boolean): void;
  /** All views at once: frees the canvas and flies out to fit everything. */
  showOverview(instant?: boolean): void;
  overviewCam(): Cam;
  flyView(id: ViewId, instant?: boolean): void;
  /** Flies to a window: snapped to its column's stop, with the column scrolled to the window. */
  focusWindow(rec: WinRec, instant?: boolean, keepFree?: boolean): void;
  /** After the camera rests: the view that contains the camera centre (else the nearest) becomes the current one. */
  updateCurrentView(): void;
  dispose(): void;
  /** Listens for lock changes (and the first paint). */
  onLockChange(listener: () => void): () => void;
}

export function createNav(cx: Ctx): Nav {
  const { camera, state, views, world, viewport } = cx;
  const cam = camera.cam;
  const listeners = new Set<() => void>();
  const paintLock = (): void => {
    world.toggleAttribute("data-snap", state.canvasLock);
    viewport.toggleAttribute("data-snap", state.canvasLock);
    for (const l of listeners) l();
  };
  const stopsFor = (c: ViewRec): Stops => stops(c.view, cx.view.contentRect(c), camera.vw, camera.vh);
  const nearestStop = (c: ViewRec, x: number): number => nearest(stopsFor(c), x);
  /**
   * How far the docked sidebar covers the canvas area, in pixels from its left edge (0 when it is not docked).
   * The canvas area itself never moves when the sidebar docks; framing moves only if the sidebar would cover it.
   */
  const insetLeft = (): number => {
    if (cx.stage.dataset.sidebar !== "docked") return 0;
    const sidebar = cx.stage.querySelector<HTMLElement>("#sidebar");
    if (!sidebar) return 0;
    return Math.max(0, sidebar.offsetLeft + sidebar.offsetWidth + 12 - cx.core.panes.offsetLeft);
  };
  const snapCam = (c: ViewRec, i: number): Cam => {
    const st = stopsFor(c);
    state.snapIdx = clamp(i, 0, st.lefts.length - 1);
    const left = st.lefts[state.snapIdx]!;
    let camX = left + st.view / 2;
    // The framed content's left and right edges on screen at this stop. If the docked sidebar covers its left edge,
    // centre it in the free area (or, when it is wider than that, start it at the sidebar's edge); otherwise the
    // framing does not move at all.
    const inset = insetLeft();
    if (inset > 0) {
      const r = cx.view.contentRect(c);
      const L = (Math.max(r.x, left) - left) * st.z, R = (Math.min(r.x + r.w, left + st.view) - left) * st.z;
      if (L < inset) {
        const free = camera.vw - inset, W = R - L;
        camX -= ((W <= free ? inset + (free - W) / 2 : inset) - L) / st.z;
      }
    }
    return { cx: camX, cy: st.cy, z: st.z };
  };
  const applyCanvasLock = (on: boolean): void => { state.canvasLock = on; paintLock(); };
  const goStop = (c: ViewRec, i: number, instant = false): void => { camera.flyTo(() => snapCam(c, i), instant); };
  const overviewCam = (): Cam => {
    const frames = [...views.values()].map(cx.view.frameOf);
    if (!frames.length) return camera.fit({ x: 0, y: 0, w: 1, h: 1 }, 0.92, 1);
    // Room above each frame for the view's label.
    const withLabels: Rect[] = frames.map((f) => ({ x: f.x, y: f.y - 70, w: f.w, h: f.h + 70 }));
    return camera.fit(bounds(withLabels), 0.92, 1);
  };
  const flyView = (id: ViewId, instant = false): void => {
    const c = views.get(id);
    if (!c) return;
    state.currentView = id;
    applyCanvasLock(true);
    cx.pill.paint();
    goStop(c, 0, instant);
  };
  // Docking or undocking the sidebar re-frames the current stop on the layout spring (a no-op when nothing is covered).
  const dockWatch = new MutationObserver(() => {
    const c = views.get(state.currentView);
    if (state.canvasLock && c) cx.camera.layoutFlight(() => goStop(c, state.snapIdx));
  });
  dockWatch.observe(cx.stage, { attributes: true, attributeFilter: ["data-sidebar"] });
  return {
    dispose() { dockWatch.disconnect(); },
    stopsFor, nearestStop, goStop, applyCanvasLock, overviewCam, flyView,
    setCanvasLock(on, instant = false) {
      applyCanvasLock(on);
      const c = views.get(state.currentView);
      if (on && c) goStop(c, nearestStop(c, cam.cx), instant);
    },
    showOverview(instant = false) { applyCanvasLock(false); camera.flyTo(overviewCam, instant); },
    focusWindow(rec, instant = false, keepFree = false) {
      const c = rec.owner;
      if (keepFree && !state.canvasLock) {
        // The canvas lock stays off until a view switch or a fly-in: centre the window at the current zoom.
        const r = camera.worldRect(rec.card.root);
        camera.flyTo(() => ({ cx: r.x + r.w / 2, cy: r.y + r.h / 2, z: cam.z }), instant);
        return;
      }
      if (c.view.layout !== "tiled") { flyView(c.view.id, instant); return; }
      state.currentView = c.view.id; applyCanvasLock(true); cx.pill.paint();
      const colEl = rec.card.root.parentElement as HTMLElement;
      const cols = [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")];
      let left = 0;
      for (const col of cols) { if (col === colEl) break; left += (Number(col.dataset.w) || state.metrics.colW) + COLUMN_GAP; }
      const st = stopsFor(c);
      const target = cx.view.contentRect(c).x + left;
      let best = 0;
      st.lefts.forEach((l, i) => { if (Math.abs(l - target) < Math.abs(st.lefts[best]! - target)) best = i; });
      goStop(c, best, instant);
      scrollToWindow(colEl, rec.card.root, instant);
    },
    updateCurrentView() {
      // The view actually framed: the one whose frame contains the camera centre; between views (free panning) the
      // one whose frame is nearest. Distance to a frame's centre is wrong for a wide view (Settings' last window is
      // nearer to its neighbour's centre than to its own), so it is never used.
      let best: ViewRec | undefined, bestD = Infinity;
      for (const c of views.values()) {
        const f = cx.view.frameOf(c);
        const dx = Math.max(f.x - cam.cx, 0, cam.cx - (f.x + f.w)), dy = Math.max(f.y - cam.cy, 0, cam.cy - (f.y + f.h));
        const d = Math.hypot(dx, dy);
        if (d < bestD) { best = c; bestD = d; }
      }
      if (best && best.view.id !== state.currentView) { state.currentView = best.view.id; cx.pill.paint(); }
    },
    onLockChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
}
