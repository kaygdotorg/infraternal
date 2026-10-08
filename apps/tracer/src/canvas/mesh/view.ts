/** Builds the Mesh view's model from a mesh source: its nodes as laid out, at the origin until the canvas places it. */
import type { Metrics } from "../layout/geometry";
import type { ViewModel } from "../model/types";
import type { MeshSource } from "./source";

export function meshView(source: MeshSource, m: Metrics): ViewModel {
  const { nodes, size } = source.layout(m);
  return { id: "mesh", name: "Mesh", layout: "graph", cols: [], nodes, graph: size, x: 0, y: 0 };
}
