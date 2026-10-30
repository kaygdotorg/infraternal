/**
 * The Mesh API as the canvas speaks it (#108, D163-D167, D180, D187): the actions and events, and the one place
 * where untrusted JSON from the server becomes typed data.
 *
 * Transport: control-stream actions (`Call`/`Result`) and one event topic (`Subscribe`/`Event`) on the multiplexed
 * WebSocket (contracts/plugin.md §3 and §5). The shapes are the server's own (crates/infraternal-server/src/
 * mesh_api.rs, branch mesh-api):
 *
 * | action              | input                                              | output                    |
 * |---------------------|----------------------------------------------------|---------------------------|
 * | `mesh.list`         | `{}`                                               | a `MeshSnapshot`          |
 * | `mesh.grant.create` | `{ name, from, to, both_ways }`                    | `{ grant_id, revision }`  |
 * | `mesh.grant.move`   | `{ name, side: "from" \| "to", endpoint }`          | `{ revision }`            |
 * | `mesh.grant.rename` | `{ name, new_name }`                               | `{ revision }`            |
 * | `mesh.grant.delete` | `{ name }`                                         | `{ revision }`            |
 * | `mesh.node.rename`  | `{ node_id, name }`                                | `{ revision }`            |
 *
 * An endpoint is `{ "Node": <id> }` or `{ "Tag": "<name>" }`. A grant is referenced by its name (D180); its arrow id
 * is stable across renames, so the canvas keys arrows by it. A subscription is `{ "topic": "mesh" }`; its events are
 * `{ "type": "snapshot" | "resync", "snapshot": <a list> }` (the canvas applies it), `{ "type": "changed",
 * "revision": n }` (it invalidates: the canvas lists again, coalesced, so a missed event costs nothing) and
 * `{ "type": "error", "error": "<word>" }` (the subscription is over; `forbidden` means the view is withdrawn).
 *
 * A node's `live` and `path` come from the server's own device (#236): `live` while the server's Mesh is On (the
 * server) or a WireGuard session with the node is up (a peer), `path: "direct"` for such a session; neither needs a
 * stored observation, so `last_seen` may be null on a live node. Its `host` is the machine's name.
 *
 * What the server does not send yet, and the canvas reads as absent (never invented), is marked PROPOSED and is on
 * the issue: `access` (what the person may do, D187), a node's `os`, `address`, `via`, `behind` and the `relay`
 * path. Without `access` everyone is read-only (least privilege).
 *
 * Inside the canvas a node is its host name and a tag is `tag:<name>` (D164); this module converts at the edge.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";

export type NodeState = "online" | "behind" | "offline";
export type NodePath = "direct" | "relay";

export interface WireNode {
  /** The server's stable node id (the canvas shows and keys by `name`). */
  id: number;
  name: string;
  tags: string[];
  state: NodeState;
  rttMs: number | undefined;
  os: HostPlatform | undefined;
  address: string | undefined;
  path: NodePath | undefined;
  via: string | undefined;
}
export interface WireGrant {
  /** The arrow's stable id, as a string. */
  id: string;
  name: string;
  /** Endpoints as the canvas names them: a host name or `tag:<name>`. */
  from: string;
  to: string;
  both: boolean;
  via: string | undefined;
}
export interface WireAccess { view: boolean; manageGrants: boolean }
export interface Snapshot {
  rev: number;
  /** PROPOSED. Absent from the server today: then the person may view, and may not edit. */
  access: WireAccess;
  nodes: WireNode[];
  /** Tag name (without the `tag:` prefix) to the names of its member hosts. */
  tags: Record<string, string[]>;
  grants: WireGrant[];
}

/** The two things the adapter needs from the connection; the product passes the `MuxConnection`. */
export interface MeshTransport {
  /** Runs an action. Rejects with `ActionRefused` when the server says no (unknown action or not allowed). */
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Runs the listener now if the connection is up, and after every reconnect. Returns the function that stops it. */
  onReady(listener: () => void): () => void;
  /**
   * Subscribes to topic events; `onOpen` runs on each (re)connect so the owner can resync. Returns unsubscribe.
   * Only called once the server has answered an action of the feature: a server that does not know a subscription
   * closes the connection, so the canvas never subscribes to something the server has not shown it serves.
   */
  subscribe(topic: string, onEvent: (event: Record<string, unknown>) => void, onOpen: () => void): () => void;
}

export { ActionRefused } from "../../connection";

export const ACTION = {
  list: "mesh.list",
  create: "mesh.grant.create",
  move: "mesh.grant.move",
  rename: "mesh.grant.rename",
  remove: "mesh.grant.delete",
  nodeRename: "mesh.node.rename",
} as const;
export const TOPIC = "mesh";

// ---- endpoints ------------------------------------------------------------------------------------------------------
/** The canvas's name for an endpoint to the server's. A host name needs the id table; a tag does not. */
export function endpointJson(end: string, idOf: ReadonlyMap<string, number>): Record<string, unknown> | undefined {
  if (end.startsWith("tag:")) return { Tag: end.slice(4) };
  const id = idOf.get(end);
  return id === undefined ? undefined : { Node: id };
}

// ---- parsing untrusted JSON ----------------------------------------------------------------------------------------
const MAX_NODES = 20_000, MAX_GRANTS = 100_000, MAX_TEXT = 200, MAX_TAGS = 2_000;
const PLATFORMS: readonly string[] = ["ubuntu", "debian", "redhat", "proxmox", "nixos", "apple", "unknown"];
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;
const optText = (v: unknown): string | undefined => (text(v) ? v : undefined);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

function parseAccess(v: unknown): WireAccess | undefined {
  if (!isObject(v) || typeof v.view !== "boolean" || typeof v.manage_grants !== "boolean") return undefined;
  // Managing grants without seeing them makes no sense; a server that says so is wrong, and the safe reading wins.
  return { view: v.view, manageGrants: v.view && v.manage_grants };
}

function parseNode(v: unknown): WireNode | undefined {
  if (!isObject(v)) return undefined;
  const core = isObject(v.node) ? v.node : v; // `{ node: { id, host, tags }, live, ... }`
  if (!count(core.id) || !text(core.host)) return undefined;
  const tags = Array.isArray(core.tags) && core.tags.every(text) && core.tags.length <= MAX_TAGS ? (core.tags as string[]) : [];
  const state: NodeState = v.live === true ? (v.behind === true ? "behind" : "online") : "offline";
  const rtt = v.last_rtt_us;
  const rttMs = typeof rtt === "number" && Number.isFinite(rtt) && rtt >= 0 && rtt < 60_000_000 ? rtt / 1000 : undefined;
  const os = typeof v.os === "string" && PLATFORMS.includes(v.os) ? (v.os as HostPlatform) : undefined;
  const path = v.path === "direct" || v.path === "relay" ? v.path : undefined;
  return { id: core.id, name: core.host, tags, state, rttMs, os, address: optText(v.address), path, via: optText(v.via) };
}

function parseEndpoint(v: unknown, nameOf: ReadonlyMap<number, string>): string | undefined {
  if (!isObject(v)) return undefined;
  if (text(v.Tag)) return `tag:${v.Tag}`;
  if (count(v.Node)) return nameOf.get(v.Node);
  return undefined; // a user endpoint (stage 2) or one the person may not see
}

function parseGrant(v: unknown, nameOf: ReadonlyMap<number, string>): WireGrant | undefined {
  if (!isObject(v) || !text(v.name) || !isObject(v.arrow) || !count(v.arrow.id)) return undefined;
  const from = parseEndpoint(v.arrow.from, nameOf), to = parseEndpoint(v.arrow.to, nameOf);
  if (!from || !to) return undefined;
  return { id: `g${v.arrow.id}`, name: v.name, from, to, both: v.arrow.both_ways === true, via: optText(v.via) };
}

/** Reads a `mesh.list` result. Returns nothing when it is not one (the canvas then shows its error state). */
export function parseSnapshot(v: unknown): Snapshot | undefined {
  if (!isObject(v) || !count(v.revision) || !Array.isArray(v.nodes) || !Array.isArray(v.grants) || v.nodes.length > MAX_NODES || v.grants.length > MAX_GRANTS) return undefined;
  const nodes: WireNode[] = [];
  for (const n of v.nodes) { const p = parseNode(n); if (!p) return undefined; nodes.push(p); }
  const nameOf = new Map(nodes.map((n) => [n.id, n.name]));
  if (nameOf.size !== nodes.length) return undefined;
  const tags: Record<string, string[]> = {};
  if (v.tags !== undefined) {
    if (!Array.isArray(v.tags) || v.tags.length > MAX_TAGS) return undefined;
    for (const t of v.tags) {
      if (!isObject(t) || !text(t.name) || !Array.isArray(t.members) || t.members.length > MAX_NODES) return undefined;
      tags[t.name] = t.members.flatMap((m) => (count(m) && nameOf.has(m) ? [nameOf.get(m)!] : []));
    }
  }
  // A node's own `tags` list and the tag table say the same thing; either may be all a server sends.
  for (const n of nodes) for (const t of n.tags) { const list = (tags[t] ??= []); if (!list.includes(n.name)) list.push(n.name); }
  const grants: WireGrant[] = [];
  for (const g of v.grants) {
    if (!isObject(g)) return undefined;
    const p = parseGrant(g, nameOf);
    if (p) grants.push(p);
  }
  const access = v.access === undefined ? { view: true, manageGrants: false } : parseAccess(v.access);
  return access ? { rev: v.revision, access, nodes, tags, grants } : undefined;
}

export type MeshEvent =
  | { kind: "changed"; rev: number }
  | { kind: "snapshot"; snapshot: Snapshot }
  | { kind: "error"; reason: string };

/** Reads one event of the `mesh` subscription, or nothing when it is not one. */
export function parseEvent(v: Record<string, unknown>): MeshEvent | undefined {
  if ((v.type === "snapshot" || v.type === "resync") && v.snapshot !== undefined) {
    const snapshot = parseSnapshot(v.snapshot);
    return snapshot ? { kind: "snapshot", snapshot } : undefined;
  }
  if (v.type === "changed" && count(v.revision)) return { kind: "changed", rev: v.revision };
  if (v.type === "error" && typeof v.error === "string" && v.error.length <= 64) return { kind: "error", reason: v.error };
  return undefined;
}

/** The revision in an action's answer (and the new grant's arrow id, for a create). */
export function parseAnswer(v: unknown): { rev: number; grantId?: string } | undefined {
  if (!isObject(v) || !count(v.revision)) return undefined;
  return { rev: v.revision, ...(count(v.grant_id) ? { grantId: `g${v.grant_id}` } : {}) };
}
