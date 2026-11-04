// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Resizing a window of a row group on its own (D212 amendment, D323; issue #304), on demand (D188). A window of a row group has its own
 * width and height: a drag changes this window and no other. The track (the column) is as wide as its widest window, the band as tall as
 * its tallest, and the windows that still filled their track are pinned at the width they are drawn at when a drag begins.
 *
 * The west edge holds the window's right edge: the free space on its left takes what the width gives up, and it cannot grow west past the
 * track's left edge (the windows above and below start there). The north edge works as everywhere: free space above, the bottom holds.
 */
import type { ResizeFrame, ResizeStart } from "../../../../../packages/ui/src/window-resize";
import { currentUiScale } from "../../../../../packages/ui/src/ui-scale";
import type { Ctx, WinRec } from "../context";
import { setColumnWidth } from "../layout/column-els";
import { scrollerOf } from "../layout/columns";
import { maxColumnWidth } from "../window-sizes";

export function rowsResize(cx: Ctx, rec: WinRec): { begin(colEl: HTMLElement): ResizeStart; apply(colEl: HTMLElement, f: ResizeFrame): void } {
  const cam = cx.camera.cam;
  /** The free space left of the window when the gesture began. */
  let leftOrigin = 0;
  return {
    begin(colEl) {
      // The windows of this column that still fill their track are pinned at the width they are drawn at, so the drag cannot move them.
      for (const n of colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")) if (!n.style.width) n.style.width = `${n.offsetWidth}px`;
      const root = rec.card.root;
      leftOrigin = parseFloat(root.style.marginLeft) || 0;
      const top = (parseFloat(root.style.marginTop) || 0) * cam.z;
      return { width: root.offsetWidth * cam.z, height: root.offsetHeight * cam.z, top, minWidth: 300 * currentUiScale() * cam.z, minHeight: 160 * currentUiScale() * cam.z, maxWidth: maxColumnWidth(cx.viewport.clientWidth) * cam.z, areaHeight: (scrollerOf(colEl).clientHeight - 28) * cam.z };
    },
    apply(colEl, f) {
      const root = rec.card.root;
      let w = Math.round(f.width / cam.z);
      // West edge: the right edge holds, so the free space on the left takes what the width gives up. It cannot grow west past the
      // track's left edge (the neighbours above and below start there): the width stops where the space runs out.
      const room = f.shiftX ? leftOrigin + Math.round(f.shiftX / cam.z) : leftOrigin;
      if (room < 0) w += room;
      root.style.width = `${w}px`;
      const left = f.shiftX ? Math.max(0, room) : leftOrigin;
      root.style.marginLeft = left > 0 ? `${left}px` : "";
      // The track is as wide as its widest window; the others keep the width they have.
      let track = 0;
      for (const n of colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")) track = Math.max(track, (parseFloat(n.style.marginLeft) || 0) + (parseFloat(n.style.width) || 0));
      setColumnWidth(colEl, Math.round(track), cx.state.metrics);
      colEl.dataset.user = "1";
      root.style.height = `${Math.round(f.height / cam.z)}px`;
      root.style.marginTop = f.top > 0 ? `${Math.round(f.top / cam.z)}px` : "";
      root.style.flex = "none";
      cx.view.geometry(rec.owner);
      cx.invalidate();
    },
  };
}
