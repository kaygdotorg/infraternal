/**
 * Whether the Mesh view exists (D187: views follow grants). The view is offered once the server has said the
 * person may see the mesh, and withdrawn when it says they may not; while the first snapshot is on its way a
 * view the person already had stays (loading), so its pinned nodes are not dropped from the saved layout.
 *
 * Product and mockups both use this, so the rule is tested once, against the fake server.
 */
import type { Ctx } from "../context";
import type { MeshSource } from "./source";
import { meshView } from "./view";

/** Keeps the Mesh view in step with `source`. Returns the function that stops it. */
export function offerMeshView(cx: Ctx, source: MeshSource, options: { keep?: boolean } = {}): () => void {
  const sync = (): void => {
    const have = cx.views.get("mesh");
    const status = source.status();
    if (!have && status === "ready" && source.canView()) {
      cx.view.addBeside(meshView(source, cx.state.metrics), "settings");
      cx.pill.paint();
      cx.toolbar.update();
      cx.store.changed(); // the view is part of the saved layout from now on
    } else if (have && (status === "unavailable" || (status === "ready" && !source.canView()))) {
      const wasHere = cx.state.currentView === "mesh";
      cx.view.remove(have);
      if (wasHere) cx.nav.flyView("console");
      cx.tree.render();
      cx.pill.paint();
      cx.toolbar.update();
    }
  };
  // A person who already has the view sees it at once, loading.
  if (options.keep && !cx.views.has("mesh")) cx.view.addBeside(meshView(source, cx.state.metrics), "settings");
  const off = source.onChange(sync);
  sync();
  return off;
}
