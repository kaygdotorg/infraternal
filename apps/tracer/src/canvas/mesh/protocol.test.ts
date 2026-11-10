/** The Mesh API's shapes (protocol.ts): what the server sends becomes typed data, and nothing else does. */
import { expect, test } from "bun:test";
import { endpointJson, parseAnswer, parseEvent, parseSnapshot } from "./protocol";

// Exactly what serde writes for the server's `MeshSnapshot` today (crates/infraternal-server/src/mesh_api.rs).
const today = {
  revision: 7,
  nodes: [
    { node: { id: 1, public_key: Array.from({ length: 32 }, (_, i) => i), host: "build-01", tags: ["ci"] }, live: true, last_seen: 1_700_000_000, last_rtt_us: 42_500 },
    { node: { id: 2, public_key: Array.from({ length: 32 }, () => 9), host: "edge-arm", tags: [] }, live: false, last_seen: null, last_rtt_us: null },
  ],
  tags: [{ name: "ci", members: [1] }, { name: "ops", members: [] }],
  grants: [
    { name: "ci→edge", arrow: { id: 3, from: { Tag: "ci" }, to: { Node: 2 }, both_ways: false, ports: "All" } },
    { name: "swap", arrow: { id: 4, from: { Node: 1 }, to: { Node: 2 }, both_ways: true, ports: { Ports: [{ protocol: "Tcp", number: 22 }] } } },
    { name: "later", arrow: { id: 5, from: { User: 9 }, to: { Node: 2 }, both_ways: false, ports: "All" } },
  ],
};

test("the server's own list becomes nodes, tags and grants, by name", () => {
  const s = parseSnapshot(today)!;
  expect(s.rev).toBe(7);
  expect(s.nodes.map((n) => [n.name, n.state, n.rttMs])).toEqual([["build-01", "online", 42.5], ["edge-arm", "offline", undefined]]);
  expect(s.tags).toEqual({ ci: ["build-01"], ops: [] });
  // A user endpoint (stage 2) is not drawn; both_ways is kept; the arrow's id is the stable key.
  expect(s.grants.map((g) => [g.id, g.name, g.from, g.to, g.both])).toEqual([["g3", "ci→edge", "tag:ci", "edge-arm", false], ["g4", "swap", "build-01", "edge-arm", true]]);
});

test("without `access` (today's server) the person may view and may not edit", () => {
  expect(parseSnapshot(today)!.access).toEqual({ view: true, manageGrants: false });
  expect(parseSnapshot({ ...today, access: { view: true, manage_grants: true } })!.access).toEqual({ view: true, manageGrants: true });
  // Managing what you cannot see is read as not managing.
  expect(parseSnapshot({ ...today, access: { view: false, manage_grants: true } })!.access).toEqual({ view: false, manageGrants: false });
  expect(parseSnapshot({ ...today, access: { view: "yes" } })).toBeUndefined();
});

test("fields the server does not send are absent, never invented", () => {
  const n = parseSnapshot(today)!.nodes[0]!;
  expect([n.os, n.address, n.path, n.via, n.restoreSafe]).toEqual([undefined, undefined, undefined, undefined, undefined]);
  const extra = parseSnapshot({ ...today, nodes: [{ ...today.nodes[0], os: "debian", address: "10.254.0.4", path: "relay", via: "fra", behind: true }, today.nodes[1]] })!.nodes[0]!;
  expect([extra.os, extra.address, extra.path, extra.via, extra.state]).toEqual(["debian", "10.254.0.4", "relay", "fra", "behind"]);
  expect(parseSnapshot({ ...today, nodes: [{ ...today.nodes[0], os: "plan9" }, today.nodes[1]] })!.nodes[0]!.os).toBeUndefined();
});

test("restore safety is preserved for an explicitly unsafe node", () => {
  const snapshot = parseSnapshot({
    ...today,
    nodes: [{ ...today.nodes[0], restore_safe: false }, today.nodes[1]],
  })!;
  expect(snapshot.nodes[0]).toMatchObject({ restoreSafe: false });
});

test("a server without restore-safety support leaves the field absent", () => {
  const node = parseSnapshot(today)!.nodes[0]!;
  expect(node.restoreSafe).toBeUndefined();
  expect(Object.hasOwn(node, "restoreSafe")).toBe(false);
});

// The server since #236: liveness from its own device (no stored observation, so `last_seen` is null), the path
// while a session is up, and each machine under its own name. Owner report 2026-10-17: minipc01 passing traffic.
const presence = {
  revision: 4,
  nodes: [
    { node: { id: 1, public_key: Array.from({ length: 32 }, () => 1), host: "monitor01", tags: [] }, live: true, last_seen: null, last_rtt_us: null },
    { node: { id: 3, public_key: Array.from({ length: 32 }, () => 3), host: "minipc01", tags: [] }, live: true, last_seen: null, last_rtt_us: null, path: "direct" },
  ],
  tags: [],
  grants: [],
};

test("a node the server sees passing traffic is online, on its path, under its machine's name", () => {
  const s = parseSnapshot(presence)!;
  expect(s.nodes.map((n) => [n.name, n.state, n.path])).toEqual([["monitor01", "online", undefined], ["minipc01", "online", "direct"]]);
});

test("anything that is not a list is refused, whole", () => {
  for (const bad of [null, [], "x", {}, { ...today, revision: -1 }, { ...today, revision: 1.5 }, { ...today, nodes: "no" }, { ...today, nodes: [{ live: true }] }, { ...today, tags: [{ name: "", members: [] }] }]) expect(parseSnapshot(bad)).toBeUndefined();
  // Two nodes with one id would make an endpoint ambiguous.
  expect(parseSnapshot({ ...today, nodes: [today.nodes[0], today.nodes[0]] })).toBeUndefined();
  expect(parseSnapshot({ ...today, nodes: Array.from({ length: 20_001 }, (_, i) => ({ node: { id: i, host: `h${i}` }, live: true })) })).toBeUndefined();
});

test("a node's own tag list and the tag table agree even when a server sends only one", () => {
  const onlyNode = parseSnapshot({ revision: 1, nodes: [{ node: { id: 1, host: "a", tags: ["x"] }, live: true }], grants: [] })!;
  expect(onlyNode.tags).toEqual({ x: ["a"] });
});

test("the subscription's events: a pushed list, a revision that invalidates, and the end of the subscription", () => {
  expect(parseEvent({ type: "changed", revision: 9 })).toEqual({ kind: "changed", rev: 9 });
  for (const type of ["snapshot", "resync"]) expect(parseEvent({ type, snapshot: today })).toMatchObject({ kind: "snapshot", snapshot: { rev: 7 } });
  expect(parseEvent({ type: "error", error: "forbidden" })).toEqual({ kind: "error", reason: "forbidden" });
  for (const bad of [{ type: "changed" }, { type: "changed", revision: "9" }, { type: "changed", revision: -1 }, { type: "snapshot" }, { type: "snapshot", snapshot: {} }, { type: "other" }, {}]) expect(parseEvent(bad)).toBeUndefined();
});

test("answers carry the new revision, and a create the new arrow's id", () => {
  expect(parseAnswer({ revision: 4 })).toEqual({ rev: 4 });
  expect(parseAnswer({ revision: 4, grant_id: 12 })).toEqual({ rev: 4, grantId: "g12" });
  expect(parseAnswer({ grant_id: 12 })).toBeUndefined();
});

test("endpoints go out as the server writes them: a node by id, a tag by name", () => {
  const ids = new Map([["build-01", 1]]);
  expect(endpointJson("build-01", ids)).toEqual({ Node: 1 });
  expect(endpointJson("tag:ci", ids)).toEqual({ Tag: "ci" });
  expect(endpointJson("ghost", ids)).toBeUndefined();
});
