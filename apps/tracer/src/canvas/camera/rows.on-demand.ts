// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where the camera may go in a view of rows of windows (Settings, #304), on demand (D188): a plain view never loads it.
 *
 * - `limit`: the furthest left edge for the row being shown. A shorter row than the longest ends where its last window ends, plus the
 *   group's inset; the canvas never scrolls into the empty tracks after it. The drawn boxes decide, because the group's padding and gaps
 *   are not in the model's widths.
 * - `windowInView`: the window the person sees. Its column is the camera's stop (a window at the first or last stop sits at the screen's
 *   edge, not its middle) and its row is the band drawn nearest the middle of the screen. The breadcrumb names it.
 * - `follow`: once a scroll or a flight has come to rest, the camera goes back inside the row's end, and an active window that is
 *   less than half on screen hands over to the window in view (D323).
 */
import type { Ctx, ViewRec } from "../context";
import { nearestStop, type Stops } from "../layout/stops";

export interface Rows {
  limit(c: ViewRec, st: Stops, band?: number): number | undefined;
  windowInView(c: ViewRec): string | undefined;
  follow(): void;
}

export function createRows(cx: Ctx, stopsFor: (c: ViewRec) => Stops, goStop: (c: ViewRec, i: number) => void): Rows {
  const { camera, state, views } = cx;
  const grouped = (c: ViewRec): boolean => c.view.layout === "tiled" && c.view.cols.some((col) => col.group !== undefined);
  const middle = (): number => { const s = cx.stage.getBoundingClientRect(); return s.top + s.height / 2; };
  /** The row (band) drawn nearest the middle of the screen. */
  const bandInView = (c: ViewRec): number | undefined => {
    const my = middle();
    let best: number | undefined, bestD = Infinity;
    for (const col of c.view.cols) for (const w of col.wins) {
      const box = c.wins.get(w.id)?.card.root.getBoundingClientRect();
      if (!box || box.width === 0 || w.row === undefined) continue;
      const d = Math.abs(box.top + box.height / 2 - my);
      if (d < bestD) { best = w.row; bestD = d; }
    }
    return best;
  };
  const limit = (c: ViewRec, st: Stops, given?: number): number | undefined => {
    const band = given ?? bandInView(c);
    if (!grouped(c) || band === undefined) return undefined;
    // World x of a window's right edge from the layout (offsets inside the view's content), not from where it is drawn: the camera moves
    // while this is asked for, and a drawn box and the camera's position are not from the same frame.
    const content = cx.view.contentRect(c);
    let right = -Infinity, widest = -Infinity;
    for (const col of c.view.cols) for (const w of col.wins) {
      const root = c.wins.get(w.id)?.card.root;
      if (!root) continue;
      let x = 0, el: HTMLElement | null = root;
      while (el && el !== c.content) { x += el.offsetLeft; el = el.offsetParent as HTMLElement | null; }
      if (!el) continue;
      const edge = content.x + x + root.offsetWidth;
      widest = Math.max(widest, edge);
      if (w.row === band) right = Math.max(right, edge);
    }
    // The row ends with the same inset the longest row ends with at the end of the view (the group's padding), so every row's last
    // window sits the same distance from the screen's edge.
    return right === -Infinity ? undefined : Math.max(st.lefts[0]!, right + (content.x + content.w - widest) - st.view);
  };
  const windowInView = (c: ViewRec): string | undefined => {
    const st = stopsFor(c), band = bandInView(c);
    const owner = st.owners[nearestStop(st, camera.cam.cx)] ?? -1;
    // The window of the row in view that sits in the stop's column; a short row has none there, and its last window is the one in view.
    let before: string | undefined, after: string | undefined;
    c.view.cols.forEach((col, k) => {
      const win = col.wins.find((w) => w.row === band);
      if (!win) return;
      if (k <= owner) before = win.id; else after ??= win.id;
    });
    return before ?? after;
  };
  const visibleShare = (el: HTMLElement): number => {
    const r = el.getBoundingClientRect(), s = cx.stage.getBoundingClientRect();
    const w = Math.min(r.right, s.right) - Math.max(r.left, s.left), h = Math.min(r.bottom, s.bottom) - Math.max(r.top, s.top);
    return r.width * r.height > 0 && w > 0 && h > 0 ? (w * h) / (r.width * r.height) : 0;
  };
  const follow = (): void => {
    const c = views.get(state.currentView);
    if (!c || !state.canvasLock || !grouped(c) || camera.isMoving) return;
    const st = stopsFor(c), end = limit(c, st);
    if (end !== undefined && camera.cam.cx - st.view / 2 > end + 1) goStop(c, state.snapIdx);
    const active = state.activeWin, id = windowInView(c), next = id ? c.wins.get(id) : undefined;
    if (active && active.owner === c && next && next !== active && visibleShare(active.card.root) < 0.5) cx.win.setActive(next);
  };
  return { limit, windowInView, follow };
}
