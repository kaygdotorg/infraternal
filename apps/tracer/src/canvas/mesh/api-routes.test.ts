/**
 * Subnet routes through the product's Mesh adapter (D197 M3, #580): the routes come with the mesh for the owner and not
 * for anyone else, every change is shown at once and settled by the server, and a refusal puts things back with a sentence.
 * The server is the fake one (`mock/mesh-server.ts`), which holds routes and refuses as the real one does.
 */
import { expect, test } from "bun:test";
import { createMeshApi } from "./api";
import { parseSnapshot } from "./protocol";
import { routesSource, type MeshNetwork } from "./networks";
import { FakeMeshServer, seedMesh } from "../mock/mesh-server";
import type { MeshSource } from "./source";

/** Fake timers: the adapter needs `window.setTimeout` and no DOM. */
function timers(): () => void {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { setTimeout: () => 1, clearTimeout: () => undefined, setInterval: () => 1, clearInterval: () => undefined } });
  return () => { if (prior) Object.defineProperty(globalThis, "window", prior); else Reflect.deleteProperty(globalThis, "window"); };
}
/** Lets the fake server's microtask answers and the adapter's follow-up lists run. */
const settle = async (): Promise<void> => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

/** A four-host mesh with an approved network (two arrows to it) and a waiting one, and the adapter primed on it. */
async function meshWithRoutes(owner = true): Promise<{ server: FakeMeshServer; source: MeshSource; done(): void }> {
  const restore = timers();
  const server = new FakeMeshServer(seedMesh([]));
  server.routeOwner = owner;
  server.setRoutes([
    { network: "192.168.10.0/24", node: "build-01", advertised: true, approved: true, declined: false, masquerade: true, arrows: ["tag:ops", "nix-cache"] },
    { network: "10.20.0.0/16", node: "edge-arm", advertised: true, approved: false, declined: false, masquerade: true },
  ]);
  const source = createMeshApi({ transport: server, prime: parseSnapshot(server.listJson())! });
  await settle();
  return { server, source, done: () => { source.dispose(); server.dispose(); restore(); } };
}
/** The network with this address in the registered routes source (the test fails loudly if there is none). */
const byCidr = (cidr: string): MeshNetwork => routesSource()!.list().find((n) => n.cidr === cidr)!;

test("the owner gets the routes with the mesh, and arrows to a network are read as network ends", async () => {
  const { source, done } = await meshWithRoutes();
  try {
    const routes = routesSource()!;
    expect(routes.list().map((n) => [n.cidr, n.state, n.router])).toEqual([["10.20.0.0/16", "pending", "edge-arm"], ["192.168.10.0/24", "approved", "build-01"]]);
    const approved = byCidr("192.168.10.0/24");
    expect(source.grants().filter((g) => g.to === approved.id).map((g) => g.from).sort()).toEqual(["nix-cache", "tag:ops"]);
    expect(routes.arrowsTo(approved.id)).toBe(2);
    // The Mesh view draws both (waiting and approved).
    expect(source.data().networks?.map((n) => n.cidr).sort()).toEqual(["10.20.0.0/16", "192.168.10.0/24"]);
  } finally { done(); }
});

test("someone who is not the owner is refused once and sees no network", async () => {
  const { server, source, done } = await meshWithRoutes(false);
  try {
    expect(routesSource()).toBeUndefined();
    expect(source.data().networks ?? []).toEqual([]);
    const asked = server.calls.filter((c) => c.action === "mesh.route.list").length;
    server.addNode({ name: "new-host" });
    await settle();
    expect(server.calls.filter((c) => c.action === "mesh.route.list").length).toBe(asked); // it stopped asking
  } finally { done(); }
});

test("approve and decline show at once; a decline leaves the Mesh view and is remembered by the server", async () => {
  const { server, source, done } = await meshWithRoutes();
  try {
    const waiting = byCidr("10.20.0.0/16");
    const approving = routesSource()!.approve(waiting.id);
    expect(waiting.state).toBe("approved"); // optimistic
    expect(waiting.saving).toBe(true);
    await approving;
    await settle();
    expect(server.calls.find((c) => c.action === "mesh.route.approve")?.input).toEqual({ node_id: 2, network: "10.20.0.0/16", masquerade: true });
    expect(byCidr("10.20.0.0/16").saving).toBeUndefined();
    server.advertise("nix-cache", ["172.20.0.0/16"]);
    await settle();
    const noisy = byCidr("172.20.0.0/16");
    await routesSource()!.decline(noisy.id);
    await settle();
    expect(byCidr("172.20.0.0/16").state).toBe("declined");
    expect(source.data().networks?.some((n) => n.cidr === "172.20.0.0/16")).toBe(false);
    server.advertise("nix-cache", []); server.advertise("nix-cache", ["172.20.0.0/16"]);
    await settle();
    expect(byCidr("172.20.0.0/16").state).toBe("declined");
  } finally { done(); }
});

test("an overlapping approval is refused in the owner's words, and the network waits again", async () => {
  const { server, done } = await meshWithRoutes();
  try {
    server.advertise("edge-arm", ["10.20.0.0/16", "192.168.0.0/16"]);
    await settle();
    const wide = byCidr("192.168.0.0/16");
    // The list already says why (the server's reason, without its route number).
    expect(wide.refusal?.short).toBe("Overlaps 192.168.10.0/24");
    await expect(routesSource()!.approve(wide.id)).rejects.toThrow("192.168.0.0/16 overlaps 192.168.10.0/24, which is already approved. Revoke that one first");
    expect(wide.state).toBe("pending");
    expect(wide.refusal?.sentence).not.toContain("route ");
  } finally { done(); }
});

test("revoke takes the arrows off at once; a lost answer brings them and the approval back", async () => {
  const { server, source, done } = await meshWithRoutes();
  try {
    const net = byCidr("192.168.10.0/24");
    server.failNext("mesh.route.revoke", "network");
    const revoking = routesSource()!.revoke(net.id);
    expect(net.state).toBe("pending");
    expect(source.grants().filter((g) => g.to === net.id)).toHaveLength(0);
    await expect(revoking).rejects.toThrow("Could not stop routing 192.168.10.0/24. Check your connection");
    expect(net.state).toBe("approved");
    expect(source.grants().filter((g) => g.to === net.id)).toHaveLength(2);
    // Now for real: the network waits again under a new identity, with no arrows.
    await routesSource()!.revoke(net.id);
    await settle();
    const again = byCidr("192.168.10.0/24");
    expect(again.state).toBe("pending");
    expect(again.id).not.toBe(net.id);
    expect(source.grants().some((g) => g.to.startsWith("net:"))).toBe(false);
  } finally { done(); }
});

test("keep-source is an approval with masquerade off, and goes back when refused", async () => {
  const { server, done } = await meshWithRoutes();
  try {
    const net = byCidr("192.168.10.0/24");
    await routesSource()!.setKeepSource(net.id, true);
    await settle();
    expect(server.routeList().find((r) => r.network === "192.168.10.0/24")?.masquerade).toBe(false);
    expect(byCidr("192.168.10.0/24").keepSource).toBe(true);
    server.failNext("mesh.route.approve", "refuse");
    await expect(routesSource()!.setKeepSource(net.id, false)).rejects.toThrow("Only the server's owner can");
    expect(byCidr("192.168.10.0/24").keepSource).toBe(true);
  } finally { done(); }
});
