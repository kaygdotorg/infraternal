/**
 * The Mesh API as the canvas speaks it (#108, D163-D167, D180, D187): the action and event shapes, and the one
 * place where untrusted JSON from the server becomes typed data.
 *
 * Transport: control-stream actions (`Call`/`Result`) and one event topic (`Subscribe`/`Event`) on the multiplexed
 * WebSocket (contracts/plugin.md §3 and §5). Actions:
 *
 * | action              | input                          | output            |
 * |---------------------|--------------------------------|-------------------|
 * | `mesh.snapshot`     | `{}`                           | a `Snapshot`      |
 * | `mesh.grant.create` | `{ from, to, via?, name? }`    | `{ grant, rev }`  |
 * | `mesh.grant.move`   | `{ id, from?, to? }`           | `{ grant, rev }`  |
 * | `mesh.grant.rename` | `{ id, name }`                 | `{ grant, rev }`  |
 * | `mesh.grant.delete` | `{ id }`                       | `{ rev }`         |
 *
 * Events on topic `mesh` carry the revision they produce (`rev`) and one `change`. A client that sees a gap in
 * the revisions, or that reconnects, asks for a new snapshot: events sent while the socket was down are not
 * replayed.
 *
 * Endpoints are written the way the canvas shows them: a host's name, or `tag:<name>` (D164). A grant's `id` is its
 * stable reference; its `name` is what people read and rename (D180: edges carry names only, never rules, ports
 * or ranges). `auto` means the name follows the grant's ends, so the server renames it when an end moves.
 * The server decides what a person may do (D187) and audits every change (D154 G9); `access` only tells the
 * canvas which controls to offer.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";

export type NodeState = "online" | "behind" | "offline";
export type NodePath = "direct" | "relay";

export interface WireNode {
  /** The host's name, unique in the mesh (`<name>.internal`, D165). */
  name: string;
  os: HostPlatform | undefined;
  /** The mesh address as shown (IPv4, D165). */
  address: string | undefined;
  state: NodeState;
  rttMs: number | undefined;
  path: NodePath | undefined;
  /** The relay a relayed path goes through. */
  via: string | undefined;
}
export interface WireGrant { id: string; name: string; auto: boolean; from: string; to: string; via: string | undefined }
export interface WireAccess { view: boolean; manageGrants: boolean }
export interface Snapshot {
  rev: number;
  access: WireAccess;
  nodes: WireNode[];
  /** Tag name (without the `tag:` prefix) to the names of its member hosts. */
  tags: Record<string, string[]>;
  grants: WireGrant[];
}

export type Change =
  | { kind: "node"; node: WireNode }
  | { kind: "node.removed"; name: string }
  | { kind: "tags"; tags: Record<string, string[]> }
  | { kind: "grant"; grant: WireGrant }
  | { kind: "grant.removed"; id: string }
  | { kind: "access"; access: WireAccess };
export interface MeshEvent { rev: number; change: Change }

/** The two things the adapter needs from the connection; the product passes the `MuxConnection`. */
export interface MeshTransport {
  /** Runs an action. Rejects with `ActionRefused` when the server says no (unknown action or not allowed). */
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Subscribes to topic events; `onOpen` runs on each (re)connect so the owner can resync. Returns unsubscribe. */
  subscribe(topic: string, onEvent: (event: Record<string, unknown>) => void, onOpen: () => void): () => void;
}

export { ActionRefused } from "../../connection";

export const ACTION = {
  snapshot: "mesh.snapshot",
  create: "mesh.grant.create",
  move: "mesh.grant.move",
  rename: "mesh.grant.rename",
  remove: "mesh.grant.delete",
} as const;
export const TOPIC = "mesh";

// ---- parsing untrusted JSON ----------------------------------------------------------------------------------
const MAX_NODES = 20_000, MAX_GRANTS = 100_000, MAX_TEXT = 200, MAX_TAGS = 2_000;
const PLATFORMS: readonly string[] = ["ubuntu", "debian", "redhat", "proxmox", "nixos", "apple", "unknown"];
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;
const optText = (v: unknown): string | undefined => (text(v) ? v : undefined);
const rev = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

export function parseAccess(v: unknown): WireAccess | undefined {
  if (!isObject(v) || typeof v.view !== "boolean" || typeof v.manage_grants !== "boolean") return undefined;
  // Managing grants without seeing them makes no sense; a server that says so is wrong, and the safe reading wins.
  return { view: v.view, manageGrants: v.view && v.manage_grants };
}

export function parseNode(v: unknown): WireNode | undefined {
  if (!isObject(v) || !text(v.name)) return undefined;
  const state = v.state;
  if (state !== "online" && state !== "behind" && state !== "offline") return undefined;
  const os = typeof v.os === "string" && PLATFORMS.includes(v.os) ? (v.os as HostPlatform) : undefined;
  const rttMs = typeof v.rtt_ms === "number" && Number.isFinite(v.rtt_ms) && v.rtt_ms >= 0 && v.rtt_ms < 60_000 ? v.rtt_ms : undefined;
  const path = v.path === "direct" || v.path === "relay" ? v.path : undefined;
  return { name: v.name, os, address: optText(v.address), state, rttMs, path, via: optText(v.via) };
}

export function parseGrant(v: unknown): WireGrant | undefined {
  if (!isObject(v) || !text(v.id) || !text(v.name) || !text(v.from) || !text(v.to)) return undefined;
  return { id: v.id, name: v.name, auto: v.auto === true, from: v.from, to: v.to, via: optText(v.via) };
}

export function parseTags(v: unknown): Record<string, string[]> | undefined {
  if (!isObject(v)) return undefined;
  const keys = Object.keys(v);
  if (keys.length > MAX_TAGS) return undefined;
  const out: Record<string, string[]> = {};
  for (const k of keys) {
    const members = v[k];
    if (!text(k) || !Array.isArray(members) || members.length > MAX_NODES || !members.every(text)) return undefined;
    out[k] = members as string[];
  }
  return out;
}

export function parseSnapshot(v: unknown): Snapshot | undefined {
  if (!isObject(v) || !rev(v.rev) || !Array.isArray(v.nodes) || !Array.isArray(v.grants) || v.nodes.length > MAX_NODES || v.grants.length > MAX_GRANTS) return undefined;
  const access = parseAccess(v.access);
  const tags = parseTags(v.tags ?? {});
  if (!access || !tags) return undefined;
  const nodes: WireNode[] = [];
  for (const n of v.nodes) { const p = parseNode(n); if (!p) return undefined; nodes.push(p); }
  const grants: WireGrant[] = [];
  for (const g of v.grants) { const p = parseGrant(g); if (!p) return undefined; grants.push(p); }
  return { rev: v.rev, access, nodes, tags, grants };
}

export function parseEvent(v: Record<string, unknown>): MeshEvent | undefined {
  if (v.topic !== TOPIC || !rev(v.rev) || !isObject(v.change)) return undefined;
  const c = v.change;
  switch (c.kind) {
    case "node": { const node = parseNode(c.node); return node ? { rev: v.rev, change: { kind: "node", node } } : undefined; }
    case "node.removed": return text(c.name) ? { rev: v.rev, change: { kind: "node.removed", name: c.name } } : undefined;
    case "tags": { const tags = parseTags(c.tags); return tags ? { rev: v.rev, change: { kind: "tags", tags } } : undefined; }
    case "grant": { const grant = parseGrant(c.grant); return grant ? { rev: v.rev, change: { kind: "grant", grant } } : undefined; }
    case "grant.removed": return text(c.id) ? { rev: v.rev, change: { kind: "grant.removed", id: c.id } } : undefined;
    case "access": { const access = parseAccess(c.access); return access ? { rev: v.rev, change: { kind: "access", access } } : undefined; }
    default: return undefined;
  }
}

/** The result of a grant action: the grant as the server now has it, and the revision that produced it. */
export function parseGrantResult(v: unknown): { grant: WireGrant; rev: number } | undefined {
  if (!isObject(v) || !rev(v.rev)) return undefined;
  const grant = parseGrant(v.grant);
  return grant ? { grant, rev: v.rev } : undefined;
}
