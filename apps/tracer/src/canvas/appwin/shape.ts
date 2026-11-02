/**
 * Shapes an app-window canvas card to the machine's stream dimensions. This module is reached only through the
 * app-window on-demand body, keeping its feature-specific resize logic out of every canvas session's deferred bundle.
 */
import { shapeFor } from "../../../../../packages/ui/src/window-resize";
import type { Ctx, WinRec } from "../context";
import { scrollerOf } from "../layout/columns";
import { resizeHost } from "../windows/frame";

/** How long a window takes to settle into a remote window's new shape. */
const SHAPE_MS = 180;
/**
 * A resize host refits the body at the end; the body then asks for its shape again. This guard prevents that nested
 * call from using an animated layout height and repeatedly changing the target.
 */
const shaping = new WeakSet<WinRec>();

/** Fits the picture area to the remote aspect when this window has a plain resizable column. */
export function shapeStreamWindow(cx: Ctx, rec: WinRec, inner: HTMLElement, aspect: number): boolean {
  if (rec.owner.view.layout !== "tiled" || rec.model.splitOf || rec.owner.view.team) return false;
  const root = rec.card.root;
  const colEl = root.parentElement;
  if (!colEl || scrollerOf(colEl) !== colEl || colEl.querySelectorAll(":scope > .ui-window").length !== 1) return false;
  if (shaping.has(rec) || inner.clientWidth < 2 || inner.clientHeight < 2) return false;
  const z = cx.camera.cam.z;
  const host = resizeHost(cx, rec);
  const start = host.begin();
  // A height set by an earlier shape may still be easing: its target is the written style, not the animated layout.
  const written = Number.parseFloat(root.style.height);
  // Grow only into the room the person can see right of the window's left edge: a wider shape lowers the height
  // instead, so the window (and its edges) stays on screen where it was opened.
  const viewport = cx.viewport.getBoundingClientRect();
  const room = (viewport.right - root.getBoundingClientRect().left - 16) / z;
  const box = {
    width: start.width / z, height: Number.isFinite(written) ? written : start.height / z,
    chromeWidth: root.offsetWidth - inner.clientWidth, chromeHeight: root.offsetHeight - inner.clientHeight,
    minWidth: start.minWidth / z, maxWidth: Math.max(start.minWidth / z, Math.min(start.maxWidth / z, room)),
    minHeight: start.minHeight / z, maxHeight: (start.areaHeight - start.top) / z,
  };
  const next = shapeFor(box, aspect);
  if (next.width === box.width && next.height === box.height) return false;
  // The new frame eases in; the picture inside keeps filling it (object-fit) while it moves.
  const animated = !matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (animated) {
    colEl.classList.add("is-shaping");
    root.classList.add("is-shaping");
    window.setTimeout(() => { colEl.classList.remove("is-shaping"); root.classList.remove("is-shaping"); }, SHAPE_MS + 40);
  }
  shaping.add(rec);
  try {
    host.apply({ width: next.width * z, height: next.height * z, top: start.top, shiftX: 0 });
    host.end();
  } finally {
    shaping.delete(rec);
  }
  return true;
}
