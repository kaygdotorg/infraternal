/**
 * Moving a window by its pill (structure, D119): the card lifts out of its column into the view's lift layer,
 * a slot marks where it will land, the other windows reflow around the slot on the shared FLIP spring, and on
 * release the card springs into the slot with a little overshoot and rejoins the column. Dropping left or right
 * of the outer columns makes a new column; a column left empty collapses.
 *
 * The gesture listens on `window` because re-parenting the card into the lift layer drops its pointer capture.
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import type { Ctx, ViewRec, WinRec } from "../context";
import { el } from "../dom";
import { columnRect, columnEls } from "../layout/columns";
import { COLUMN_GAP } from "../layout/geometry";
import { freshColumnId, fromGrid, applyCols, readColumns } from "../views/tracks";
import { groupOf, insertBand, problems, removeWin, runsOf, settle, type Col } from "../layout/grid";
import { SCALE_REST, quarterDevicePx, restAt } from "../springs";
import { endActivity, setActivity } from "../../perf-activity";

export function beginMove(cx: Ctx, rec: WinRec, first: PointerEvent, start: { x: number; y: number }): void {
  const { camera, state, flip } = cx;
  const cam = camera.cam;
    const c = rec.owner;
    if (c.view.layout !== "tiled") return;
    cx.details?.close(true);
    state.movingWindow = true;
    setActivity("drag");
    cx.view.hideSummary();
    const root = rec.card.root;
    const rect0 = root.getBoundingClientRect();
    const contentBox = c.content.getBoundingClientRect();
    const slot = el("div", "cl-slot");
    slot.style.height = `${rect0.height / cam.z}px`;
    slot.style.flex = "none";
    const colEl = root.parentElement as HTMLElement;
    // A window in a group, or one that spans, lands through the grid (D212): the layout as it is now, before the lift, is
    // what the landing works from. A plain window keeps the flat path.
    const cols0 = readColumns(cx, c);
    const grid0 = (rec.model.span ?? 1) > 1 || !!groupOf(runsOf(cols0), columnEls(c.colsEl).indexOf(colEl)) ? { cols: cols0, w: Number(colEl.dataset.w) || state.metrics.colW, h: root.offsetHeight } : undefined;
    colEl.insertBefore(slot, root);
    const fixedH = root.style.height;
    root.classList.add("is-lifted");
    root.style.cssText = `position:absolute;left:${(rect0.left - contentBox.left) / cam.z}px;top:${(rect0.top - contentBox.top) / cam.z}px;width:${rect0.width / cam.z}px;height:${rect0.height / cam.z}px;margin:0`;
    c.lift.append(root);
    let dx = 0, dy = 0;
    const applyMoveTransform = (): void => { root.style.transform = `translate(${dx}px, ${dy}px) scale(${root.style.getPropertyValue("--lift") || 1})`; cx.invalidate(); };
    const lift = new Spring(1, (s) => { root.style.setProperty("--lift", String(s)); applyMoveTransform(); }, { visualDuration: 0.3, bounce: 0.3 });
    restAt(lift, SCALE_REST);
    lift.set(1.025);
    const target = { col: colEl as HTMLElement | undefined, index: 0, fresh: false };
    const place = (clientX: number, clientY: number): void => {
      const cols = columnEls(c.colsEl);
      const rects = cols.map((x) => columnRect(x));
      let nextCol: HTMLElement | undefined, fresh = false;
      if (rects.length && clientX < rects[0]!.left - 20 * cam.z) fresh = true;
      else if (rects.length && clientX > rects[rects.length - 1]!.right + 20 * cam.z) fresh = true;
      if (!fresh) {
        let best = Infinity;
        cols.forEach((x, i) => { const r = rects[i]!; const d = clientX < r.left ? r.left - clientX : clientX > r.right ? clientX - r.right : 0; if (d < best) { best = d; nextCol = x; } });
      }
      const before = flip.measure(flip.targets(c.colsEl));
      let slotCol: HTMLElement;
      if (fresh || !nextCol) {
        const atStart = rects.length > 0 && clientX < rects[0]!.left;
        slotCol = cx.view.newCol({ id: freshColumnId(cx, c), w: Number((colEl as HTMLElement).dataset.w) || state.metrics.colW, wins: [] });
        if (atStart) c.colsEl.prepend(slotCol); else c.colsEl.append(slotCol);
        slotCol.append(slot);
      } else {
        slotCol = nextCol;
        const wins = [...slotCol.querySelectorAll<HTMLElement>(":scope > .ui-window")].filter((w) => w !== root);
        const index = wins.filter((w) => { const r = w.getBoundingClientRect(); return r.top + r.height / 2 < clientY; }).length;
        const ref = wins[index] ?? null;
        if (slot.parentElement === slotCol && slot.nextElementSibling === ref) return;
        slotCol.insertBefore(slot, ref);
      }
      // Columns left empty collapse; the ones to their right glide over.
      for (const x of columnEls(c.colsEl)) if (!x.children.length) x.remove();
      target.col = slotCol;
      cx.view.geometry(c);
      flip.play(before);
    };
    const move = (e: PointerEvent): void => {
      if (e.pointerId !== first.pointerId) return;
      dx = (e.clientX - start.x) / cam.z; dy = (e.clientY - start.y) / cam.z;
      applyMoveTransform();
      place(e.clientX, e.clientY);
    };
    const finish = (e: PointerEvent): void => {
      if (e.pointerId !== first.pointerId) return;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", finish);
      const slotRect = slot.getBoundingClientRect();
      const now = root.getBoundingClientRect();
      // Land: the window springs from where it is to the slot (a little overshoot), then joins the column.
      const gx = (now.left - slotRect.left) / cam.z, gy = (now.top - slotRect.top) / cam.z;
      const contentNow = c.content.getBoundingClientRect();
      root.style.left = `${(slotRect.left - contentNow.left) / cam.z}px`;
      root.style.top = `${(slotRect.top - contentNow.top) / cam.z}px`;
      root.style.width = `${slotRect.width / cam.z}px`;
      root.style.height = `${slotRect.height / cam.z}px`;
      const land = new Spring(1, (p) => {
        const s = 1 + 0.025 * Math.max(0, p);
        root.style.transform = `translate(${gx * p}px, ${gy * p}px) scale(${s})`;
        cx.invalidate();
        if (p !== 0) return;
        root.style.cssText = fixedH ? `height:${fixedH}` : "";
        root.classList.remove("is-lifted");
        // Through the grid when the window was in one (D212): where it landed is read from the slot and the windows around it.
        const landedAt = grid0 ? landing(cx, c, rec, grid0, slot) : undefined;
        slot.replaceWith(root);
        if (grid0) applyCols(cx, c, fromGrid(c, landedAt ?? settle(grid0.cols)));
        state.movingWindow = false;
        endActivity("drag");
        cx.view.geometry(c);
        cx.view.settle(c.view.id);
        cx.tree.render();
        cx.store.changed();
      }, { visualDuration: 0.42, bounce: 0.3 });
      restAt(land, Math.min(SCALE_REST, quarterDevicePx() / Math.max(1, Math.abs(gx), Math.abs(gy))));
      land.set(0);
    };
    // Re-parenting the card into the lift layer drops its pointer capture, so the gesture listens on the window.
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish);
    window.addEventListener("pointercancel", finish);
    move(first);
  }

/**
 * Where a window dropped on a grid lands (D212): the layout it was taken from, without it (its space given to its
 * neighbours, as a close does), with it inserted as a new band of the column the slot is in, above the window that is
 * below the slot. A slot in a new column makes a plain column at that place. Returns nothing when no valid place
 * exists, and the window goes back where it was.
 */
function landing(cx: Ctx, c: ViewRec, rec: WinRec, grid0: { cols: ReturnType<typeof readColumns>; w: number; h: number }, slot: HTMLElement): Col[] | undefined {
  const id = rec.model.id;
  const base = removeWin(grid0.cols, id, COLUMN_GAP);
  const colEl = slot.parentElement as HTMLElement | null;
  if (!colEl) return undefined;
  const slotTop = slot.getBoundingClientRect().top;
  const below = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")]
    .filter((n) => n !== rec.card.root && n.getBoundingClientRect().top > slotTop)
    .map((n) => n.dataset.windowId);
  const next: Col[] = [...base];
  const N = { id, span: 1, rows: 1, row: 0, h: grid0.h > 0 ? grid0.h : undefined };
  const at = next.findIndex((col) => col.id === colEl.dataset.id);
  let out: Col[];
  if (at >= 0) {
    const col = next[at]!;
    const belowWin = below.map((b) => col.wins.find((w) => w.id === b)).find((w) => w !== undefined);
    const bottom = Math.max(0, ...col.wins.map((w) => w.row + w.rows));
    const runRows = Math.max(0, ...next.flatMap((x) => x.wins.map((w) => w.row + w.rows)));
    const rowAt = belowWin ? belowWin.row : bottom || runRows;
    out = insertBand(next, at, rowAt, { id, span: 1, h: N.h });
  } else {
    // A new column: it takes its place among the columns, by where its element stands in the view.
    const els = columnEls(c.colsEl);
    const pos = els.indexOf(colEl);
    const before = els.slice(0, pos).map((e) => e.dataset.id);
    const index = next.filter((col) => before.includes(col.id)).length;
    const colId = colEl.dataset.id ?? freshColumnId(cx, c);
    const fresh: Col = { id: colId, w: grid0.w, wins: [{ id, span: 1, rows: 1, row: 0, ...(N.h !== undefined ? { h: N.h } : {}) }] };
    next.splice(index, 0, fresh);
    out = settle(next);
  }
  return problems(out).length ? undefined : out;
}
