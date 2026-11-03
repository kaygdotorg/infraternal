/**
 * Mockup Mesh: the real adapter (`mesh/api.ts`) over a fake server (`mesh-server.ts`).
 *
 * The canvas builds its Mesh module once, with one source, but a mockup scene may start from a different mesh
 * (the seed, a large one, one that is loading, one that fails). The proxy below is that one source; `reset` swaps
 * the adapter and server behind it and tells the canvas the mesh changed. Everything the canvas sees comes
 * through the real adapter, so the specs exercise the code the product runs.
 *
 * URL switches (review only): `?mesh=1000` a generated mesh of that many hosts, `?mesh=loading`, `?mesh=error`,
 * `?mesh=empty`, `?mesh=denied`; `?meshgrants=n` adds n more grants to a generated mesh.
 */
import type { Grant } from "../model/types";
import { createMeshApi } from "../mesh/api";
import { parseSnapshot } from "../mesh/protocol";
import type { MeshSource } from "../mesh/source";
import { FakeMeshServer, generateMesh, seedMesh, type FakeMeshSeed, type FakeMeshState } from "./mesh-server";
import { INITIAL_GRANTS } from "./data";
import type { MockWorld } from "./world";

export interface MockMesh extends MeshSource {
  readonly server: FakeMeshServer;
  /** Starts again from the scene's mesh. Listeners stay; the canvas is told the mesh changed. */
  reset(): void;
  /** The pins the person made, by node (what the canvas would save). */
  pins(): Record<string, { x: number; y: number }>;
}

export function createMockMesh(world: MockWorld): MockMesh {
  const listeners = new Set<() => void>();
  const failures = new Set<(m: string) => void>();
  const pinned = new Map<string, { x: number; y: number }>();
  const params = new URLSearchParams(location.search);
  const mode = params.get("mesh") ?? "";
  const extra = Number(params.get("meshgrants") ?? "0") || 0;
  let server: FakeMeshServer;
  let inner: MeshSource;
  let offs: Array<() => void> = [];

  const build = (): void => {
    for (const off of offs) off();
    inner?.dispose();
    server?.dispose();
    const count = /^\d+$/.test(mode) ? Number(mode) : 0;
    const seed: FakeMeshSeed = count ? generateMesh(count, extra) : mode === "empty" ? { nodes: [], tags: {}, grants: [] } : seedMesh(INITIAL_GRANTS);
    const state: FakeMeshState = mode === "loading" ? "loading" : mode === "error" ? "error" : mode === "denied" ? "denied" : "ready";
    server = new FakeMeshServer(seed, state);
    // `?meshserver=today`: the server as it is now, without the fields the issue proposes (access, os, address, relay).
    if (params.get("meshserver") === "today") { server.includeAccess = false; server.includeExtras = false; }
    // Only an operator holds Mesh grants in the mockup (D187); everyone else gets the refusal a server would give.
    server.access = world.role === "operator" ? { view: true, manageGrants: true } : { view: false, manageGrants: false };
    // The scene's grants are the server's: the Settings panel and the probe read them from the world.
    world.grants = server.grantList().map((g): Grant => ({ id: g.id, from: g.from, to: g.to, ...(g.via ? { via: g.via } : {}) }));
    inner = createMeshApi({
      transport: server,
      pins: Object.fromEntries(pinned),
      ...(state === "ready" ? { prime: parseSnapshot(server.listJson())! } : {}),
    });
    offs = [inner.onChange(() => { for (const id of [...pinned.keys()]) if (!inner.data().pins.has(id)) pinned.delete(id); syncWorld(); for (const l of [...listeners]) l(); }), inner.onFailure((m) => { for (const f of [...failures]) f(m); })];
  };
  const syncWorld = (): void => { world.grants = inner.grants().map((g) => ({ id: g.id, from: g.from, to: g.to, ...(g.via ? { via: g.via } : {}) })); };
  build();

  return {
    get server() { return server; },
    reset() { build(); for (const l of [...listeners]) l(); },
    pins: () => Object.fromEntries(pinned),
    data: () => inner.data(),
    grants: () => inner.grants(),
    tags: () => inner.tags(),
    status: () => inner.status(),
    canView: () => inner.canView(),
    canEdit: () => inner.canEdit(),
    retry: () => inner.retry(),
    addGrant: (from, to) => inner.addGrant(from, to),
    moveGrant: (g, to) => inner.moveGrant(g, to),
    renameGrant: (g, name) => inner.renameGrant(g, name),
    removeGrant: (g) => inner.removeGrant(g),
    renameNode(name, newName) {
      return inner.renameNode(name, newName).then(() => { const pin = pinned.get(name); if (pin) { pinned.delete(name); pinned.set(newName.trim(), pin); } });
    },
    pin(id, x, y) { pinned.set(id, { x: Math.round(x), y: Math.round(y) }); inner.pin(id, x, y); },
    onChange(l) { listeners.add(l); return () => { listeners.delete(l); }; },
    onFailure(l) { failures.add(l); return () => { failures.delete(l); }; },
    dispose() { for (const off of offs) off(); inner.dispose(); server.dispose(); },
  };
}
