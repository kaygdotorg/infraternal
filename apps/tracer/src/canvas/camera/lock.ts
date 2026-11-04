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
import { columnEls, scrollToWindow } from "../layout/columns";
import { drawnWidthOf } from "../layout/column-els";
import { isFreeView, nearestStop as nearest, stopsFor as stops, type Stops } from "../layout/stops";
import { onDemand } from "../../on-demand";
import { bounds, clamp, type Cam } from "./camera";

export interface Nav {
  stopsFor(c: ViewRec): Stops;
  nearestStop(c: ViewRec, cx: number): number;
  /** `band` is the row the camera will show; absent, the row drawn nearest the middle of the screen. */
  goStop(c: ViewRec, i: number, instant?: boolean, band?: number): void;
  /**
   * In a view of rows of windows (Settings): the window in view. Its column is the camera's stop (a window at the first or last
   * stop sits at the screen's edge, not its middle) and its row is the band drawn nearest the middle of the screen. The breadcrumb
   * names it and the active window follows it (D323).
   */
  windowInView(c: ViewRec): string | undefined;
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
  /** The camera or a row came to rest: see `follow`. */
  settled(): void;
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
  const stopsFor = (c: ViewRec): Stops => stops(c.view, cx.view.contentRect(c), camera.vw, camera.vh, state.metrics.narrow, state.metrics.minW, state.metrics.maxW);
  const nearestStop = (c: ViewRec, x: number): number => nearest(stopsFor(c), x);
  const rowGroups = (c: ViewRec): boolean => c.view.layout === "tiled" && c.view.cols.some((col) => col.group !== undefined);
  // The rules for a view of rows of windows (Settings) load once such a view exists (D188): `camera/rows.on-demand.ts`.
  let rows: import("./rows.on-demand").Rows | undefined, rowsLoading = false;
  const ensureRows = (c: ViewRec): void => {
    if (rows || rowsLoading || !rowGroups(c)) return;
    rowsLoading = true;
    void onDemand(() => import("./rows.on-demand")).then((m) => { rows = m.createRows(cx, stopsFor, (v, i) => { goStop(v, i); }); }, () => { rowsLoading = false; });
  };
  const snapCam = (c: ViewRec, i: number, band?: number): Cam => {
    const st = stopsFor(c);
    let idx = clamp(i, 0, st.lefts.length - 1), left = st.lefts[idx]!;
    ensureRows(c);
    const limit = rows?.limit(c, st, band);
    if (limit !== undefined && left > limit) {
      left = limit;
      idx = st.lefts.reduce((best, l, k) => (l <= limit ? k : best), 0);
    }
    state.snapIdx = idx;
    return { cx: left + st.view / 2, cy: st.cy, z: st.z };
  };
  const applyCanvasLock = (on: boolean): void => { state.canvasLock = on; paintLock(); };
  const goStop = (c: ViewRec, i: number, instant = false, band?: number): void => { camera.flyTo(() => snapCam(c, i, band), instant); };
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
    // A graph too big to snap node by node opens fitted whole and free: zoom into a cluster from there.
    applyCanvasLock(!isFreeView(c.view));
    cx.pill.paint();
    goStop(c, 0, instant);
  };
  let settleTimer = 0;
  const settle = (): void => { window.clearTimeout(settleTimer); settleTimer = window.setTimeout(() => { rows?.follow(); }, 160); };
  viewport.addEventListener("scroll", settle, { capture: true, passive: true, signal: cx.signal });
  return {
    settled: settle,
    stopsFor, nearestStop, goStop, windowInView: (c) => rows?.windowInView(c), applyCanvasLock, overviewCam, flyView,
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
      const cols = columnEls(c.colsEl);
      let left = 0;
      for (const col of cols) { if (col === colEl) break; left += (drawnWidthOf(col) || state.metrics.colW) + COLUMN_GAP; }
      // The stop that frames this column: stops are centred on their column (when the viewport is wider than it), so the
      // column's centre is compared with the stops' centres. Comparing its left edge with a stop's left edge picked the
      // NEXT column's stop on a wide viewport, which left the window at the screen's left edge, or off it, with its
      // neighbour out of view (#141).
      const colW = drawnWidthOf(colEl) || state.metrics.colW;
      const st = stopsFor(c);
      const content = cx.view.contentRect(c).x;
      // A window of a group (D212): when the whole group fits the viewport, the camera rests on the group's middle, so a
      // half is never framed with the other half and the spanning window's header cut off the screen (the minimum shift).
      const group = colEl.parentElement?.classList.contains("cl-group") ? colEl.parentElement : undefined;
      const members = group ? [...group.querySelectorAll<HTMLElement>(":scope > .cl-col")] : [];
      const gw = members.reduce((sum, col) => sum + drawnWidthOf(col), 0) + COLUMN_GAP * Math.max(0, members.length - 1);
      if (group && gw <= st.view) {
        const first = members[0]!;
        let gLeft = 0;
        for (const col of cols) { if (col === first) break; gLeft += (drawnWidthOf(col) || state.metrics.colW) + COLUMN_GAP; }
        const centre = content + gLeft + gw / 2;
        state.snapIdx = nearest(st, centre);
        camera.flyTo(() => ({ cx: centre, cy: st.cy, z: st.z }), instant);
      } else {
        // The stop that frames this column: stops are centred on their column (when the viewport is wider than it), so the
        // column's centre is compared with the stops' centres. Comparing its left edge with a stop's left edge picked the
        // NEXT column's stop on a wide viewport, which left the window at the screen's left edge, or off it, with its
        // neighbour out of view (#141).
        goStop(c, nearest(st, content + left + colW / 2), instant, rec.model.row);
      }
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
