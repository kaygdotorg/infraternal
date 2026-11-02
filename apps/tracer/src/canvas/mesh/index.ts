/**
 * The Mesh (D164, D180, D194): who may reach what, drawn only in the Mesh view.
 *
 * The Mesh view is a graph of node cards (hosts and tags) joined by access arrows; dashed goes through another
 * host. Dragging an arrow's head or tail onto another node changes who can reach what; dropping it on empty canvas
 * offers to stop that access; dragging from the connector on a card onto another card offers to allow access. Arrows
 * carry a grant's name only, never its rules (D180). Nothing of this is drawn on any other view: terminal windows
 * show no arrows and no connector (D194).
 *
 * All data and all edits go through a MeshSource (source.ts, api.ts for the real one), and the Mesh view is offered
 * only when the server says the person may see it.
 *
 * The Mesh view's own code (graph-view.ts: node cards, arrows and their editing, layout, levels of detail) loads
 * the first time the view is on screen, and shows a quiet loading card until then. Everything here stays small: the
 * loader, the counts and the failure toast.
 *
 * Arrow geometry is redrawn on the next animation frame after the camera moves (updateOverlay, coalesced by the
 * context's invalidate).
 */
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import { onDemand } from "../../on-demand";
import type { Ctx, ViewRec } from "../context";
import { el } from "../dom";
import type { Grant } from "../model/types";
import type { GraphViewModule } from "./graph-view";
import type { MeshSource } from "./source";

export interface MeshModule {
  /** Fills a graph view with its node cards and arrows. */
  buildGraph(c: ViewRec): void;
  /** Shared pins changed without changing host inventory. */
  refreshLayout(c: ViewRec): void;
  /** The camera came to rest: arrows redraw when the zoom changed enough to change their head size. */
  redraw(): void;
  /** Redraws the arrows that follow the camera (called on the next frame). */
  updateOverlay(): void;
  summaryRows(c: ViewRec): string[][];
  countText(c: ViewRec): string;
  /** The grants as they are now (a copy). */
  grants(): Grant[];
  /** The graph view once its code has loaded (rename.on-demand.ts reaches it to redraw and to open a name field). */
  graph(): GraphViewModule | undefined;
  /** What the Mesh view has on screen right now (specs and the frame-time benchmark read this). */
  graphStats(): ReturnType<GraphViewModule["stats"]>;
  dispose(): void;
}

export function createMesh(cx: Ctx, source: MeshSource): MeshModule {
  const { camera } = cx;
  const cam = camera.cam;
  const updateOverlay = (): void => { if (gv) gv.cull(); else wantGraph(); };

  // ---- the Mesh view: its code loads when it is first on screen --------------------------------------------------------
  let gv: GraphViewModule | undefined;
  let loading = false, disposed = false;
  const pending = new Set<ViewRec>();
  const quiet = new Map<ViewRec, HTMLElement>();
  const onScreen = (c: ViewRec): boolean => {
    const f = cx.view.frameOf(c);
    const w = camera.vw / cam.z, h = camera.vh / cam.z;
    return f.x < cam.cx + w / 2 && f.x + f.w > cam.cx - w / 2 && f.y < cam.cy + h / 2 && f.y + f.h > cam.cy - h / 2;
  };
  /** The loading card shows only when the code takes longer than a frame; it is the loading state of the view (same card, same rhythm). */
  const showQuiet = (c: ViewRec): void => {
    requestAnimationFrame(() => {
      if (gv || disposed || quiet.has(c) || !pending.has(c)) return;
      const box = el("div", "cl-empty cl-meshstate");
      const mark = el("div", "cl-meshstate-mark");
      mark.append(createSpinner());
      box.append(mark, el("p", "cl-empty-title", "Loading the mesh"), el("p", "cl-empty-hint", "Getting your hosts and who can reach what."));
      box.setAttribute("role", "status");
      box.dataset.open = "false";
      c.content.append(box);
      quiet.set(c, box);
      requestAnimationFrame(() => { box.dataset.open = "true"; });
    });
  };
  const wantGraph = (): void => {
    if (gv || loading || !pending.size || ![...pending].some(onScreen)) return;
    loading = true;
    for (const c of pending) showQuiet(c);
    void onDemand(() => import("./mesh.on-demand")).then((mod) => {
      if (disposed) return;
      gv = mod.createGraphView(cx, source);
      for (const box of quiet.values()) box.remove();
      quiet.clear();
      for (const c of pending) gv.buildGraph(c);
      pending.clear();
    }, () => {
      // The code did not arrive (the network dropped, a new build replaced the chunk): try again at the next frame on screen.
      loading = false;
    });
  };
  const buildGraph = (c: ViewRec): void => {
    c.colsEl.classList.add("cl-graph");
    if (gv) { gv.buildGraph(c); return; }
    pending.add(c);
    wantGraph();
  };
  const redraw = (): void => { gv?.rest(); if (!gv) wantGraph(); };

  let canEdit = source.canEdit();
  const offChange = source.onChange(() => {
    const rights = source.canEdit() !== canEdit;
    canEdit = source.canEdit();
    gv?.changed(rights);
  });
  const offFailure = source.onFailure((message) => cx.toast.show({ message }));
  const hostCount = (): number => source.data().nodes.size;
  return {
    graph: () => gv,
    buildGraph, redraw, updateOverlay, refreshLayout: (c) => gv?.refresh(c),
    summaryRows: () => [["Hosts", String(hostCount())], ["Allowed access", String(source.grants().length)], ["Through another host", String(source.grants().filter((g) => g.via).length)]],
    countText: () => `${hostCount()} host${hostCount() === 1 ? "" : "s"} · ${source.grants().length} allowed`,
    grants: () => source.grants().map((g) => ({ ...g })),
    graphStats: () => gv?.stats(),
    dispose() { disposed = true; offChange(); offFailure(); for (const box of quiet.values()) box.remove(); },
  };
}
