/**
 * The Mesh adapter: where the Mesh view gets its nodes and grants, and where edits go.
 *
 * The canvas holds no mesh data of its own. A `MeshSource` is filled by the mesh API of #108 in the product
 * (`api.ts`) and by a fake server in mockups (`mock/mesh-server.ts`, behind the same `api.ts`). Without a source the
 * Mesh view is not offered, and the reach arrows and the connector on a terminal's pill do not exist.
 *
 * Rules the source follows (D164, D180, D187):
 * - A grant "A to B" lets A open connections to B; `via` names a relay. A tag stands for the hosts that carry it.
 * - Edges carry grant names only; the canvas never sees rules, ports or ranges.
 * - Graph nodes are laid out automatically by the source; nodes the person drags are pinned and saved (`pin`).
 * - Edits are optimistic: the source applies them at once, sends them, and puts things back (and says so through
 *   `onFailure`) when the server refuses or the socket drops. The server decides what a person may do.
 * - The source tells the canvas what the person may do (`canView`, `canEdit`); it never decides for the server.
 */
import type { Grant, NodeModel } from "../model/types";
import type { Cluster } from "./layout";
import type { WireNode } from "./protocol";

/**
 * Where the data stands. `unavailable`: the server has no Mesh for this person (the view is not offered).
 * `error`: it could not be reached (the view shows a retry; data from before stays on screen).
 */
export type MeshStatus = "loading" | "ready" | "error" | "unavailable";

export interface MeshLayout {
  /** Every node with its position in the graph's own coordinates. */
  nodes: NodeModel[];
  /** The graph's content size. */
  size: { w: number; h: number };
  /** How far the graph is drawn right/down of the pins' own coordinates (pins may be negative); a pin is `node - origin`. */
  origin: { x: number; y: number };
  /** Frames the far zoom draws in place of the cards; each lists the hosts it holds. */
  clusters: Cluster[];
}

/** What the source knows about the mesh, unlaid: the Mesh view's own code turns it into cards (layout-model.ts). */
export interface MeshData {
  /** Changes whenever the mesh does; a cache of anything derived from it is valid while this stays. */
  version: number;
  nodes: ReadonlyMap<string, WireNode>;
  /** Tag name (no prefix) to member host names. */
  tags: Readonly<Record<string, readonly string[]>>;
  /** Positions the person pinned. */
  pins: ReadonlyMap<string, { x: number; y: number }>;
}

export const tagNodeId = (tag: string): string => `tag:${tag}`;

export interface MeshSource {
  data(): MeshData;
  /** The grants, in a stable order. The array and its objects are live: callers read them, never change them. */
  grants(): readonly Grant[];
  /** Tags and the hosts that carry them. */
  tags(): Readonly<Record<string, readonly string[]>>;
  status(): MeshStatus;
  /** Whether the person may see the Mesh at all (D187). */
  canView(): boolean;
  /** Whether the person may change grants (arrows get handles only then). */
  canEdit(): boolean;
  /** Fetches again after an error. */
  retry(): void;
  addGrant(from: string, to: string): Grant;
  moveGrant(grant: Grant, to: { from?: string; to?: string }): void;
  renameGrant(grant: Grant, name: string): void;
  removeGrant(grant: Grant): void;
  /**
   * Renames a host (`mesh.node.rename`). Settles once the server has answered: it resolves after the new name is on
   * every grant, tag and pin that carried the old one, and rejects with a sentence for the person (a duplicate name,
   * no permission, the host gone) after leaving everything as it was. The source never shows the new name before the
   * server accepted it, because a name is a host's identity here (D180): arrows, tags and pins refer to it.
   */
  renameNode(name: string, newName: string): Promise<void>;
  /** A person dragged a node: remember where it stays. */
  pin(nodeId: string, x: number, y: number): void;
  onChange(listener: () => void): () => void;
  /** An edit did not take effect; the source has already put the grant back. */
  onFailure(listener: (message: string) => void): () => void;
  dispose(): void;
}

/** What a grant is called when nobody named it (the name the server keeps): who may reach what, in words. */
export const derivedGrantName = (from: string, to: string): string => `${from.replace(/^tag:/, "")} to ${to.replace(/^tag:/, "")}`;
/** The grant's name, or the derived one for a source without names. */
export const grantLabel = (g: Grant): string => g.name ?? derivedGrantName(g.from, g.to);
/** A host or tag as the person sees it on its card. */
export const endName = (end: string): string => end;
/** What hovering a grant says: a sentence for the ones nobody named, the person's own name for the rest. */
export const grantSentence = (g: Grant): string => (g.auto !== false && (g.name === undefined || g.name === derivedGrantName(g.from, g.to)) ? `${endName(g.from)} can reach ${endName(g.to)}` : g.name!);
