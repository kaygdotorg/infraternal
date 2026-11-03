/** Renaming a host through the Mesh API (#259): written through grants, tags and pins on success, untouched on refusal. */
import { expect, test } from "bun:test";
import { createMeshApi } from "./api";
import { ACTION, ActionRefused, type MeshTransport, type Snapshot, type WireNode } from "./protocol";

const node = (id: number, name: string, over: Partial<WireNode> = {}): WireNode =>
  ({ id, name, tags: [], state: "online", rttMs: undefined, os: undefined, address: undefined, path: undefined, via: undefined, ...over });
const prime = (): Snapshot => ({
  rev: 1, access: { view: true, manageGrants: true },
  nodes: [node(1, "build-01"), node(2, "edge-arm", { via: "build-01" }), node(3, "ops")],
  tags: { team: ["build-01", "ops"] },
  grants: [{ id: "g1", name: "build-01 to edge-arm", from: "build-01", to: "edge-arm", both: false, via: undefined }, { id: "g2", name: "ops to build-01", from: "ops", to: "build-01", both: false, via: "build-01" }],
});

/** Fake timers: the adapter needs `window.setTimeout` and no DOM. */
function timers(): () => void {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { setTimeout: () => 1, clearTimeout: () => undefined } });
  return () => { if (prior) Object.defineProperty(globalThis, "window", prior); else Reflect.deleteProperty(globalThis, "window"); };
}
const transportFor = (answer: () => Promise<unknown>, calls: Array<{ action: string; input: unknown }> = []): MeshTransport => ({
  call: (action, input) => { calls.push({ action, input }); return answer() as Promise<never>; },
  onReady: () => () => undefined,
  subscribe: () => () => undefined,
});

test("an accepted rename is sent by node id and written through every place the name was used", async () => {
  const restore = timers();
  const calls: Array<{ action: string; input: unknown }> = [];
  const source = createMeshApi({ transport: transportFor(() => Promise.resolve({ revision: 2 }), calls), prime: prime(), pins: { "build-01": { x: 5, y: 6 } } });
  try {
    await source.renameNode("build-01", "  build-02 ");
    expect(calls).toEqual([{ action: ACTION.nodeRename, input: { node_id: 1, name: "build-02" } }]);
    const data = source.data();
    expect([...data.nodes.keys()]).toEqual(["build-02", "edge-arm", "ops"]); // order kept
    expect(data.nodes.get("build-02")!.name).toBe("build-02");
    expect(data.nodes.get("edge-arm")!.via).toBe("build-02");
    expect(data.tags.team).toEqual(["build-02", "ops"]);
    expect(source.grants().map((g) => [g.from, g.to, g.via])).toEqual([["build-02", "edge-arm", undefined], ["ops", "build-02", "build-02"]]);
    expect(data.pins.get("build-02")).toEqual({ x: 5, y: 6 });
    expect(data.pins.has("build-01")).toBe(false);
  } finally { source.dispose(); restore(); }
});

test("a refused rename rejects with a plain sentence and changes nothing", async () => {
  for (const [reason, sentence] of [
    ["conflict", "Could not rename build-01: another host is already called ops."],
    ["forbidden", "Could not rename build-01: you are not allowed to rename hosts."],
    ["not found", "Could not rename build-01: it is no longer in the mesh."],
  ] as const) {
    const restore = timers();
    const source = createMeshApi({ transport: transportFor(() => Promise.reject(new ActionRefused(undefined, reason))), prime: prime() });
    try {
      await expect(source.renameNode("build-01", "ops")).rejects.toThrow(sentence);
      expect([...source.data().nodes.keys()]).toEqual(["build-01", "edge-arm", "ops"]);
      expect(source.grants()[0]!.from).toBe("build-01");
    } finally { source.dispose(); restore(); }
  }
});

test("a dropped connection says so, and a host that left the mesh is not sent at all", async () => {
  const restore = timers();
  const calls: Array<{ action: string; input: unknown }> = [];
  const source = createMeshApi({ transport: transportFor(() => Promise.reject(new Error("connection lost")), calls), prime: prime() });
  try {
    await expect(source.renameNode("build-01", "x")).rejects.toThrow("Could not rename build-01. Check your connection and try again.");
    await expect(source.renameNode("gone", "x")).rejects.toThrow("Could not rename gone: it is no longer in the mesh.");
    // The failed one is followed by a list (what the server holds may differ); the unknown host sent nothing.
    expect(calls.filter((c) => c.action === ACTION.nodeRename)).toHaveLength(1);
  } finally { source.dispose(); restore(); }
});
