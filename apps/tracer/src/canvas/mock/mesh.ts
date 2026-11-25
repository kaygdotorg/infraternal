/**
 * Mockup Mesh: the real adapter (`mesh/api.ts`) over a fake server (`mesh-server.ts`).
 *
 * The canvas builds its Mesh module once, with one source, but a mockup scene may start from a different mesh
 * (the seed, a large one, one that is loading, one that fails). The proxy below is that one source; `reset` swaps
 * the adapter and server behind it and tells the canvas the mesh changed. Everything the canvas sees comes
 * through the real adapter, so the specs exercise the code the product runs.
 *
 * URL switches (review only): `?mesh=1000` a generated mesh of that many hosts, `?mesh=loading`, `?mesh=error`,
 * `?mesh=empty`, `?mesh=denied`; `?meshgrants=n` adds n more grants to a generated mesh, `?meshnets=n` n subnet routes
 * (half approved, with arrows), `?meshowner=0` a person who is not the owner (no routes). `?routes=1` plays the subnet-route scenes on the four-host seed (`mesh-routes.ts`).
 */
import type { Grant } from "../model/types";
import { createMeshApi } from "../mesh/api";
import { parseSnapshot } from "../mesh/protocol";
import type { MeshSource } from "../mesh/source";
import { FakeMeshServer, generateMesh, seedMesh, type FakeMeshSeed, type FakeMeshState } from "./mesh-server";
import { INITIAL_GRANTS } from "./data";
import { ROUTE_SCENES, createRouteScenes } from "./mesh-routes";
import type { PaletteEntry } from "../../core-screen";
import type { MockWorld } from "./world";

/** The mockup mesh: a Mesh source whose fake server, pins and subnet-route scenes a mockup scene and the specs can reach. */
export interface MockMesh extends MeshSource {
  readonly server: FakeMeshServer;
  /** Starts again from the scene's mesh. Listeners stay; the canvas is told the mesh changed. */
  reset(): void;
  /** The pins the person made, by node (what the canvas would save). */
  pins(): Record<string, { x: number; y: number }>;
  /** `?routes=1`: the subnet-route scenes (D197 M3, #580) for the palette. Absent otherwise. */
  readonly routes?: { entries(): PaletteEntry[]; run(id: string): void };
}

/** Makes the mockup mesh for `world`: the real adapter over a fake server built from the URL's switches. */
export function createMockMesh(world: MockWorld): MockMesh {
  const listeners = new Set<() => void>();
  const failures = new Set<(m: string) => void>();
  const pinned = new Map<string, { x: number; y: number }>();
  const params = new URLSearchParams(location.search);
  const mode = params.get("mesh") ?? "";
  const extra = Number(params.get("meshgrants") ?? "0") || 0;
  const nets = Math.min(200, Number(params.get("meshnets") ?? "0") || 0);
  let server: FakeMeshServer;
  let inner: MeshSource;
  let offs: Array<() => void> = [];
  const scenes = params.get("routes") === "1"
    ? createRouteScenes(() => server, () => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:mesh.networks", source: "keyboard" } })))
    : undefined;

  const build = (): void => {
    for (const off of offs) off();
    inner?.dispose();
    server?.dispose();
    const count = /^\d+$/.test(mode) ? Number(mode) : 0;
    const seed: FakeMeshSeed = count ? generateMesh(count, extra, nets) : mode === "empty" ? { nodes: [], tags: {}, grants: [] } : seedMesh(INITIAL_GRANTS);
    const state: FakeMeshState = mode === "loading" ? "loading" : mode === "error" ? "error" : mode === "denied" ? "denied" : "ready";
    server = new FakeMeshServer(seed, state);
    // `?routes=1` opens on the first scene (an approved network with arrows and one waiting).
    if (scenes) server.setRoutes(ROUTE_SCENES[0]!.routes());
    // `?meshserver=today`: the server as it is now, without the fields the issue proposes (access, os, address, relay).
    if (params.get("meshserver") === "today") { server.includeAccess = false; server.includeExtras = false; }
    // `?meshowner=0`: the person is not the server's owner, so the server refuses to list subnet routes (D197 M3).
    if (params.get("meshowner") === "0") server.routeOwner = false;
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
    ...(scenes ? { routes: scenes } : {}),
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
