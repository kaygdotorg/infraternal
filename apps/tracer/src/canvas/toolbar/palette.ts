/**
 * The canvas in the command palette (⌘K). The rows are `palette-rows.on-demand.ts`, fetched when the palette is installed
 * (D188, #322); this module hands them to the screen and answers the rows' actions.
 *
 * Every row carries a `canvas:` action; the core screen forwards them as `tracer:canvas-action` events, which
 * this module handles. A row's `source` is "keyboard" when it was picked without the pointer, and keyboard
 * flights are the short version (camera.keyFlight).
 */
import type { PaletteEntry } from "../../core-screen";
import type { Ctx } from "../context";
import { onDemand } from "../../on-demand";

export function installPalette(cx: Ctx): () => void {
  const { core, signal, state } = cx;
  // The rows are an on-demand module (palette-rows.on-demand.ts, D188), fetched as the palette is installed: a few KB, so it is
  // there before anyone presses ⌘K. A palette opened before it arrives has no canvas rows for that moment and is redrawn when
  // it does (the open palette keeps its selection), so nothing is lost and nothing waits.
  let rows: ((cx: Ctx) => PaletteEntry[]) | undefined;
  let loading = false;
  const loadRows = (): void => {
    if (rows || loading) return;
    loading = true;
    void onDemand(() => import("./palette-rows.on-demand")).then((m) => { if (signal.aborted) return; rows = m.canvasEntries; core.refreshPalette(); }, () => { loading = false; });
  };
  loadRows();
  const removeProvider = core.addPaletteProvider(() => { if (rows) return rows(cx); loadRows(); return []; });
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<import("./palette-actions.on-demand").CanvasAction>).detail;
    if (!detail?.action?.startsWith("canvas:")) return;
    if (detail.action.startsWith("canvas:openlink:")) {
      try { cx.adapters.activeTerminal?.()?.openLinkFromPalette?.(decodeURIComponent(detail.action.slice("canvas:openlink:".length))); } catch { /* A malformed palette action has no effect. */ }
      return;
    }
    const selected = state.activeWin;
    // Loading an action never delays host registration or the initial terminal; disposal fences a late chunk.
    void onDemand(() => import("./palette-actions.on-demand")).then((module) => {
      if (!signal.aborted) module.dispatchCanvasAction(cx, detail, selected);
    }, () => core.toast.show({ message: "The action couldn't load. Check your connection and try again.", tone: "error" }));
  };
  window.addEventListener("tracer:canvas-action", onAction, { signal });
  const offHosts = cx.adapters.sessions.onChange(() => core.refreshPalette());
  const offEntries = cx.adapters.settings.outline?.onEntries?.(() => core.refreshPalette());
  return () => { offHosts(); offEntries?.(); removeProvider(); };
}
