/**
 * Builds the Mesh view's model. It starts empty: the nodes are laid out by the Mesh view's own code, which loads the
 * first time the view is on screen (`mesh.on-demand.ts`) and fills the model in then.
 */
import type { Metrics } from "../layout/geometry";
import type { ViewModel } from "../model/types";
import type { MeshSource } from "./source";

/** Makes the Mesh view's empty model (graph layout, no nodes yet). Its arguments are unused: the nodes arrive when the graph code loads. */
export function meshView(_source: MeshSource, _m: Metrics): ViewModel {
  return { id: "mesh", name: "Mesh", layout: "graph", cols: [], nodes: [], x: 0, y: 0 };
}
