/**
 * The Mesh adapter: where the Mesh view gets its nodes and grants, and where edits go.
 *
 * The canvas holds no mesh data of its own. A `MeshSource` is filled by the mesh API of #108 in the product and
 * by a test double in mockups. Without a source the Mesh view is not offered, and the reach arrows and the
 * connector on a terminal's pill do not exist.
 *
 * Rules the source follows (D164, D180):
 * - A grant "A to B" lets A open connections to B; `via` names a relay. A tag stands for the hosts that carry it.
 * - Edges carry grant names only; the canvas never sees rules, ports or ranges.
 * - Graph nodes are laid out automatically by the source; nodes the person drags are pinned and saved (`pin`).
 */
import type { Metrics } from "../layout/geometry";
import type { Grant, NodeModel } from "../model/types";

export interface MeshSource {
  /** Nodes with positions (in the graph's own coordinates) and the graph's content size. */
  layout(metrics: Metrics): { nodes: NodeModel[]; size: { w: number; h: number } };
  /** The grants, in a stable order. The array is live: callers read it, never change it. */
  grants(): readonly Grant[];
  /** Tags and the hosts that carry them. */
  tags(): Readonly<Record<string, readonly string[]>>;
  /** Whether the person may change grants (arrows get handles only then). */
  canEdit(): boolean;
  addGrant(from: string, to: string): Grant;
  moveGrant(grant: Grant, to: { from?: string; to?: string }): void;
  removeGrant(grant: Grant): void;
  /** A person dragged a node: remember where it stays. */
  pin(nodeId: string, x: number, y: number): void;
  onChange(listener: () => void): () => void;
}
