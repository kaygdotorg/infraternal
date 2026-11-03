// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Renaming a Mesh host (#259): the server call and what follows it on the canvas, and opening a host's name field from the
 * palette. An on-demand module (D188): the Mesh module holds nothing of it, because none of it is needed until a name has
 * been typed or asked for.
 */
import type { Ctx, ViewRec } from "../context";

/**
 * Resolves when the server accepted; rejects, after saying why in the shared toast, when it refused. Every pin the canvas keeps
 * under the old name moves to the new one, so a card the person placed does not jump; a graph view that has one is redrawn.
 */
export async function renameHost(cx: Ctx, id: string, name: string): Promise<void> {
  try { await cx.adapters.mesh!.renameNode(id, name); } catch (error) { cx.toast.show({ message: error instanceof Error ? error.message : `Could not rename ${id}.`, tone: "error" }); throw error; }
  const next = name.trim();
  for (const c of cx.views.values() as Iterable<ViewRec>) {
    const pins = c.view.graphPins;
    if (!pins || !(id in pins)) continue;
    pins[next] = pins[id]!;
    delete pins[id];
    if (c.view.layout === "graph") cx.mesh?.graph()?.refresh(c);
  }
  cx.store.changed();
}

/** A rename the palette asked for before the graph code or the card was there; the graph applies it when it is built. */
let pending: string | undefined;

/** Opens the inline name field on a host's card in the Mesh view; waits for the card if it is not drawn yet. */
export function beginRename(cx: Ctx, id: string): void {
  const graph = cx.mesh?.graph();
  if (graph) graph.beginRename(id); else pending = id;
}

export function takePendingRename(): string | undefined {
  const id = pending;
  pending = undefined;
  return id;
}
