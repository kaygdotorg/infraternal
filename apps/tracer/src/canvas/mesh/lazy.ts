// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The product's `MeshSource` while the real adapter (`api.ts`, with the wire code behind it) is still on its way.
 *
 * The canvas needs a source the moment it is built, to learn whether the Mesh view exists, but nothing on the first
 * screen reads mesh data. So the adapter loads on demand (`api-load.on-demand.ts`) and this thin stand-in answers
 * "loading" until it has: `offerMeshView` already waits for "ready", so the view appears when the adapter's first
 * answer arrives, only a little later than before. Once loaded every call goes straight to the adapter, and the
 * adapter's change and failure events are re-sent to the listeners registered here. A chunk that fails to load is
 * reported as "error", which the Mesh view already shows with a retry that loads again.
 */
import { onDemand } from "../../on-demand";
import type { Grant } from "../model/types";
import type { MeshApiOptions } from "./api";
import type { MeshSource } from "./source";

/**
 * Returns a `MeshSource` right away. Until the real adapter has loaded it reports status "loading" and empty data (or "error" if the
 * load failed; `retry` loads again). After that every call goes to the adapter. Edits made before it has loaded throw, but the view that makes
 * them cannot be on screen then. `dispose` also disposes the adapter.
 */
export function createLazyMeshApi(options: MeshApiOptions): MeshSource {
  const listeners = new Set<() => void>();
  const failures = new Set<(message: string) => void>();
  let inner: MeshSource | undefined;
  let failed = false;
  let disposed = false;
  const empty = { version: 0, nodes: new Map(), tags: {}, pins: new Map() };
  const changed = (): void => { for (const l of [...listeners]) l(); };
  const load = (): void => {
    void onDemand(() => import("./api-load.on-demand")).then((m) => {
      if (disposed) return;
      failed = false;
      inner = m.createMeshApi(options);
      inner.onChange(changed);
      inner.onFailure((message) => { for (const f of [...failures]) f(message); });
      changed();
    }, () => { failed = true; changed(); });
  };
  load();
  // Edits only exist once the view is on screen, which needs the adapter; these guard the impossible case.
  const need = (): MeshSource => { if (!inner) throw new Error("The mesh is not loaded yet."); return inner; };
  return {
    data: () => inner?.data() ?? empty,
    grants: () => inner?.grants() ?? [],
    tags: () => inner?.tags() ?? {},
    status: () => inner?.status() ?? (failed ? "error" : "loading"),
    canView: () => inner?.canView() ?? false,
    canEdit: () => inner?.canEdit() ?? false,
    retry() { if (inner) inner.retry(); else if (failed) load(); },
    addGrant: (from, to): Grant => need().addGrant(from, to),
    moveGrant: (g, to) => need().moveGrant(g, to),
    renameGrant: (g, name) => need().renameGrant(g, name),
    removeGrant: (g) => need().removeGrant(g),
    renameNode: (name, newName) => need().renameNode(name, newName),
    pin: (id, x, y) => need().pin(id, x, y),
    onChange(l) { listeners.add(l); return () => { listeners.delete(l); }; },
    onFailure(l) { failures.add(l); return () => { failures.delete(l); }; },
    dispose() { disposed = true; inner?.dispose(); listeners.clear(); failures.clear(); },
  };
}
