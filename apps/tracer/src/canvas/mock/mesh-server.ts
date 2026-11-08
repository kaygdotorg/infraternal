/**
 * A fake Mesh server for mockups and specs: it answers the actions and sends the events of the Mesh API
 * (`mesh/protocol.ts`, in the shapes of crates/infraternal-server/src/mesh_api.rs) from memory, so the real
 * adapter (`mesh/api.ts`) runs unchanged against it.
 *
 * What it adds to the server's shapes, because the UI needs them and the issue asks for them (PROPOSED in
 * protocol.ts): `access`, and a node's `os`, `address`, `via`, `behind` and the `relay` path. `includeAccess` /
 * `includeExtras` turn those off, which is how a server that does not send them yet is tested. A live node's
 * `direct` path is the server's own (#236) and is always sent, with `last_seen` null as the server sends it.
 *
 * Besides the happy path it can be told to misbehave, which is what the specs for the unhappy states need: stay
 * silent (loading), refuse everything (a person without Mesh grants), fail the next call, answer slowly, send
 * events before its answers or not at all, or drop and resume the connection. It can also make a large mesh
 * (`generateMesh`) and churn node status the way a live mesh does. Like the server it rejects unknown input fields,
 * and answers a refusal with the same short words (`forbidden`, `conflict`, `invalid input`, `not found`).
 *
 * Test double only; the product never imports this.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { ACTION, TOPIC, ActionRefused, type MeshTransport } from "../mesh/protocol";

export type FakeMeshState = "ready" | "loading" | "error" | "denied";
export interface FakeNode { id: number; name: string; live: boolean; behind: boolean; rttUs: number | undefined; os: HostPlatform; address: string; path: "direct" | "relay"; via: string | undefined; /** Whether the mock node can retire peers after a server restore. */ restoreSafe: boolean }
export interface FakeGrant { name: string; arrowId: number; from: string; to: string; both: boolean; via: string | undefined }
export interface FakeMeshSeed { nodes: FakeNode[]; tags: Record<string, number[]>; grants: FakeGrant[] }

const OS: HostPlatform[] = ["ubuntu", "debian", "nixos", "apple", "redhat", "proxmox"];
const derive = (from: string, to: string): string => `${from.replace(/^tag:/, "")} to ${to.replace(/^tag:/, "")}`;

/** The four hosts, two tags and seven grants the mockup has always shown. */
export function seedMesh(grants: ReadonlyArray<{ id: string; from: string; to: string; via?: string }>): FakeMeshSeed {
  const node = (id: number, name: string, os: HostPlatform, address: string, rttMs: number, over: Partial<FakeNode> = {}): FakeNode =>
    ({ id, name, live: true, behind: false, rttUs: rttMs * 1000, os, address, path: "direct", via: undefined, restoreSafe: true, ...over });
  return {
    nodes: [
      node(1, "build-01", "ubuntu", "10.69.69.71", 42),
      node(2, "edge-arm", "debian", "10.69.69.72", 188, { path: "relay", via: "fra-relay" }),
      node(3, "nix-cache", "nixos", "10.69.69.73", 31),
      node(4, "studio-mac", "apple", "100.86.4.21", 58),
    ],
    tags: { ops: [4], ci: [1] },
    grants: grants.map((g) => ({ name: derive(g.from, g.to), arrowId: Number(g.id.replace(/^g/, "")), from: g.from, to: g.to, both: false, via: g.via })),
  };
}

/** A mesh of `hosts` hosts in about hosts/40 tags with roughly one grant for every ten hosts. */
export function generateMesh(hosts: number, extraGrants = 0): FakeMeshSeed {
  const tagCount = Math.max(3, Math.round(hosts / 40));
  const tags: Record<string, number[]> = {};
  const nodes: FakeNode[] = [];
  const names: string[] = [];
  for (let i = 0; i < hosts; i++) {
    const name = `host-${String(i + 1).padStart(4, "0")}`;
    names.push(name);
    const relay = i % 11 === 0;
    nodes.push({
      id: i + 1, name, live: i % 53 !== 7, behind: i % 41 === 5, rttUs: (20 + ((i * 37) % 180)) * 1000, os: OS[i % OS.length]!,
      address: `10.254.${Math.floor(i / 250)}.${(i % 250) + 2}`, path: relay ? "relay" : "direct", via: relay ? "fra-relay" : undefined, restoreSafe: true,
    });
    if (i % 9 !== 0) {
      (tags[`team-${String(i % tagCount).padStart(2, "0")}`] ??= []).push(i + 1);
      if (i % 5 === 0) (tags[`team-${String((i + 7) % tagCount).padStart(2, "0")}`] ??= []).push(i + 1);
    }
  }
  for (let t = 0; t < tagCount; t++) tags[`team-${String(t).padStart(2, "0")}`] ??= [];
  const grants: FakeGrant[] = [];
  const add = (from: string, to: string, via?: string): void => {
    if (from !== to && !grants.some((g) => g.from === from && g.to === to)) grants.push({ name: derive(from, to), arrowId: grants.length + 1, from, to, both: false, via });
  };
  // Like a real mesh: teams reach the next team, hosts reach their neighbours in a team, and a few teams reach one host.
  const tagNames = Object.keys(tags).sort();
  const nameOf = (id: number): string => names[id - 1]!;
  tagNames.forEach((t, i) => add(`tag:${t}`, `tag:${tagNames[(i + 1) % tagNames.length]!}`));
  for (const t of tagNames) { const m = tags[t]!; for (let i = 0; i + 1 < Math.min(m.length, 8); i += 2) add(nameOf(m[i]!), nameOf(m[i + 1]!), i % 4 === 0 ? "fra-relay" : undefined); }
  for (let i = 3; i < hosts; i += 20) add(`tag:${tagNames[i % tagNames.length]!}`, names[i]!);
  for (let k = 0; k < extraGrants; k++) add(names[(k * 13) % hosts]!, names[(k * 29 + 5) % hosts]!);
  return { nodes, tags, grants };
}

export class FakeMeshServer implements MeshTransport {
  state: FakeMeshState = "ready";
  access = { view: true, manageGrants: true };
  /** Send `access` and the node extras (the issue's proposal). Off: the server as it is today. */
  includeAccess = true;
  includeExtras = true;
  /** Milliseconds every answer waits (0: the next microtask). */
  latency = 0;
  /** Send each change's event before its answer instead of after it. */
  eventFirst = false;
  /** Do not send events at all (a lossy link). */
  muted = false;
  /** Calls seen, in order (specs read these to prove what the canvas asked for). */
  readonly calls: Array<{ action: string; input: Record<string, unknown> }> = [];
  revision = 1;
  private nodes: Map<number, FakeNode>;
  private tags: Map<string, Set<number>>;
  private grants: FakeGrant[];
  private nextArrow: number;
  private failures: Array<{ action: string; error: "refuse" | "network" }> = [];
  private readonly open = new Map<number, { onEvent(e: Record<string, unknown>): void; onOpen(): void }>();
  private held: Array<() => void> = [];
  private churnTimer = 0;
  private nextSub = 1;

  constructor(seed: FakeMeshSeed, state: FakeMeshState = "ready") {
    this.nodes = new Map(seed.nodes.map((n) => [n.id, { ...n }]));
    this.tags = new Map(Object.entries(seed.tags).map(([k, v]) => [k, new Set(v)]));
    this.grants = seed.grants.map((g) => ({ ...g }));
    this.nextArrow = Math.max(0, ...this.grants.map((g) => g.arrowId)) + 1;
    this.state = state;
  }

  hostCount(): number { return this.nodes.size; }
  /** The grants as the canvas would show them (specs compare these with what is on screen). */
  grantList(): Array<{ id: string; name: string; from: string; to: string; via?: string; both: boolean }> {
    return this.grants.map((g) => ({ id: `g${g.arrowId}`, name: g.name, from: g.from, to: g.to, both: g.both, ...(g.via ? { via: g.via } : {}) }));
  }
  /** Objects per page of a list (the server pages by size; a small inventory fits one page). */
  pageSize = 400;
  /** The whole list as the server holds it (the mockup primes its adapter with this). */
  listJson(): Record<string, unknown> { return this.page(undefined, Infinity); }
  /** One page: objects in the order nodes, tags, grants from `cursor.offset`; `next_cursor` while more remain. */
  page(cursor: { revision: number; offset: number } | undefined, size: number): Record<string, unknown> {
    const nodes = [...this.nodes.values()].map((n) => ({
      node: { id: n.id, host: n.name, tags: [...this.tags].filter(([, m]) => m.has(n.id)).map(([t]) => t).sort() },
      live: n.live, last_seen: n.live && this.includeExtras ? 1_700_000_000 : null, last_rtt_us: n.rttUs ?? null,
      ...(n.live && n.path === "direct" ? { path: "direct" } : {}),
      ...(this.includeExtras ? { os: n.os, address: n.address, restore_safe: n.restoreSafe, ...(n.path === "relay" ? { path: n.path } : {}), ...(n.via ? { via: n.via } : {}), ...(n.behind ? { behind: true } : {}) } : {}),
    }));
    const end = (e: string): Record<string, unknown> => (e.startsWith("tag:") ? { Tag: e.slice(4) } : { Node: this.idOf(e) });
    const tags = [...this.tags].map(([name, m]) => ({ name, members: [...m].sort((a, b) => a - b) }));
    const grants = this.grants.map((g) => ({ name: g.name, arrow: { id: g.arrowId, from: end(g.from), to: end(g.to), both_ways: g.both, ports: "All" }, ...(this.includeExtras && g.via ? { via: g.via } : {}) }));
    // A cursor from an older revision restarts at the beginning, like the server; a page never splits an object.
    const from = cursor && cursor.revision === this.revision ? cursor.offset : 0;
    const total = nodes.length + tags.length + grants.length;
    const to = Math.min(total, from + size);
    const slice = <T>(list: T[], base: number): T[] => list.slice(Math.max(0, from - base), Math.max(0, to - base));
    return {
      revision: this.revision,
      ...(this.includeAccess ? { access: { view: this.access.view, manage_grants: this.access.manageGrants } } : {}),
      nodes: slice(nodes, 0),
      tags: slice(tags, nodes.length),
      grants: slice(grants, nodes.length + tags.length),
      ...(to < total ? { next_cursor: { revision: this.revision, offset: to } } : {}),
    };
  }

  // ---- the transport ---------------------------------------------------------------------------------------------
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.calls.push({ action, input });
    return new Promise((resolve, reject) => {
      const run = (): void => {
        const failure = this.failures.findIndex((f) => f.action === action || f.action === "*");
        if (failure >= 0) { const f = this.failures.splice(failure, 1)[0]!; reject(f.error === "refuse" ? new ActionRefused(undefined, "forbidden") : new Error("connection lost")); return; }
        try { resolve(this.answer(action, input)); } catch (e) { reject(e as Error); }
      };
      if (this.state === "loading" && action === ACTION.list) { this.held.push(run); return; }
      if (this.latency > 0) window.setTimeout(run, this.latency); else queueMicrotask(run);
    });
  }

  /** The fake connection is always up; a reconnect (`reconnect`) tells every listener. */
  private readonly ready = new Set<() => void>();
  onReady(listener: () => void): () => void {
    this.ready.add(listener);
    queueMicrotask(() => { if (this.ready.has(listener)) listener(); });
    return () => { this.ready.delete(listener); };
  }

  subscribe(topic: string, onEvent: (event: Record<string, unknown>) => void, onOpen: () => void): () => void {
    if (topic !== TOPIC) return () => undefined;
    const id = this.nextSub++;
    this.open.set(id, { onEvent, onOpen });
    // Like the server: a subscription starts with the list it would have answered.
    queueMicrotask(() => { if (!this.muted && this.open.has(id) && this.state === "ready" && this.access.view) onEvent({ type: "snapshot", snapshot: this.page(undefined, this.pageSize) }); });
    return () => { this.open.delete(id); };
  }

  // ---- misbehaviour ----------------------------------------------------------------------------------------------
  failNext(action: string, error: "refuse" | "network" = "network"): void { this.failures.push({ action, error }); }
  /** Answers the lists held back while in the `loading` state. */
  release(state: FakeMeshState = "ready"): void { this.state = state; const run = this.held; this.held = []; for (const r of run) r(); }
  /** The socket drops and comes back: events in between are lost, and every subscriber is told to resync. */
  reconnect(lose: () => void = () => undefined): void {
    lose();
    for (const l of [...this.ready]) queueMicrotask(l);
    // The connection sends every subscription again on a new socket, and the server answers each with its list.
    for (const s of this.open.values()) queueMicrotask(() => { s.onOpen(); if (this.muted) return; if (this.state === "ready" && this.access.view) s.onEvent({ type: "snapshot", snapshot: this.page(undefined, this.pageSize) }); else if (this.state === "error") s.onEvent({ type: "error", error: "mesh unavailable" }); });
  }
  /** The server fell behind a subscriber and pushes the whole list instead of the changes it missed. */
  resync(): void { for (const s of this.open.values()) s.onEvent({ type: "resync", snapshot: this.page(undefined, this.pageSize) }); }
  setAccess(access: { view: boolean; manageGrants: boolean }): void { this.access = access; this.bump(); }

  /** Changes a host the way a live mesh does (liveness, round trip) and tells the subscribers. */
  patchNode(name: string, patch: Partial<Pick<FakeNode, "live" | "behind" | "rttUs" | "path" | "via" | "address" | "os" | "restoreSafe">> & { rttMs?: number; state?: "online" | "offline" | "behind" }): void {
    const n = [...this.nodes.values()].find((o) => o.name === name);
    if (!n) return;
    const { rttMs, state, ...rest } = patch;
    Object.assign(n, rest);
    if (rttMs !== undefined) n.rttUs = rttMs * 1000;
    if (state) { n.live = state !== "offline"; n.behind = state === "behind"; }
    this.bump();
  }
  addNode(n: { name: string; os?: HostPlatform; address?: string; rttMs?: number }): void {
    const id = Math.max(0, ...this.nodes.keys()) + 1;
    this.nodes.set(id, { id, name: n.name, live: true, behind: false, rttUs: (n.rttMs ?? 10) * 1000, os: n.os ?? "unknown", address: n.address ?? `10.69.69.${id + 60}`, path: "direct", via: undefined, restoreSafe: true });
    this.bump();
  }
  removeNode(name: string): void {
    const n = [...this.nodes.values()].find((o) => o.name === name);
    if (!n) return;
    this.nodes.delete(n.id);
    for (const m of this.tags.values()) m.delete(n.id);
    this.grants = this.grants.filter((g) => g.from !== name && g.to !== name);
    this.bump();
  }
  /** Status churn: every tick a few hosts change round trip; `hz` ticks per second. */
  churn(hz: number, perTick = 5): () => void {
    window.clearInterval(this.churnTimer);
    const ids = [...this.nodes.keys()];
    let i = 0;
    this.churnTimer = window.setInterval(() => {
      for (let k = 0; k < perTick; k++) { const n = this.nodes.get(ids[(i++ * 31) % ids.length]!); if (n) n.rttUs = (10 + ((i * 17) % 220)) * 1000; }
      this.bump();
    }, 1000 / hz);
    return () => window.clearInterval(this.churnTimer);
  }
  dispose(): void { window.clearInterval(this.churnTimer); this.open.clear(); this.ready.clear(); this.held = []; }

  // ---- the actions -----------------------------------------------------------------------------------------------
  private idOf(name: string): number { return [...this.nodes.values()].find((n) => n.name === name)?.id ?? 0; }
  private end(v: unknown): string {
    if (typeof v === "object" && v !== null && !Array.isArray(v)) {
      const e = v as Record<string, unknown>;
      if (typeof e.Tag === "string" && this.tags.has(e.Tag)) return `tag:${e.Tag}`;
      if (typeof e.Node === "number") { const n = this.nodes.get(e.Node); if (n) return n.name; }
    }
    throw new ActionRefused(undefined, "invalid input");
  }
  private strict(input: Record<string, unknown>, keys: string[]): void {
    for (const k of Object.keys(input)) if (!keys.includes(k)) throw new ActionRefused(undefined, "invalid input");
    for (const k of keys) if (!(k in input)) throw new ActionRefused(undefined, "invalid input");
  }
  private name(v: unknown): string { if (typeof v !== "string" || !v || v.length > 200) throw new ActionRefused(undefined, "invalid input"); return v; }

  private answer(action: string, input: Record<string, unknown>): Record<string, unknown> {
    if (this.state === "error") throw new Error("connection lost");
    if (this.state === "denied" || !this.access.view) throw new ActionRefused(undefined, "forbidden");
    if (action === ACTION.list) {
      for (const k of Object.keys(input)) if (k !== "cursor" && k !== "tag") throw new ActionRefused(undefined, "invalid input");
      const c = input.cursor as { revision?: unknown; offset?: unknown } | undefined;
      return this.page(c && typeof c.revision === "number" && typeof c.offset === "number" ? { revision: c.revision, offset: c.offset } : undefined, this.pageSize);
    }
    if (!this.access.manageGrants) throw new ActionRefused(undefined, "forbidden");
    switch (action) {
      case ACTION.create: {
        this.strict(input, ["name", "from", "to", "both_ways"]);
        const name = this.name(input.name), from = this.end(input.from), to = this.end(input.to);
        if (from === to || this.grants.some((g) => g.name === name || (g.from === from && g.to === to))) throw new ActionRefused(undefined, "conflict");
        const arrowId = this.nextArrow++;
        this.grants.push({ name, arrowId, from, to, both: input.both_ways === true, via: undefined });
        return this.respond({ grant_id: arrowId });
      }
      case ACTION.move: {
        this.strict(input, ["name", "side", "endpoint"]);
        const g = this.grants.find((o) => o.name === input.name);
        if (!g) throw new ActionRefused(undefined, "not found");
        const side = input.side;
        if (side !== "from" && side !== "to") throw new ActionRefused(undefined, "invalid input");
        const next = this.end(input.endpoint);
        const from = side === "from" ? next : g.from, to = side === "to" ? next : g.to;
        if (from === to || this.grants.some((o) => o !== g && o.from === from && o.to === to)) throw new ActionRefused(undefined, "conflict");
        g.from = from; g.to = to;
        return this.respond({});
      }
      case ACTION.rename: {
        this.strict(input, ["name", "new_name"]);
        const g = this.grants.find((o) => o.name === input.name);
        const next = this.name(input.new_name);
        if (!g) throw new ActionRefused(undefined, "not found");
        if (this.grants.some((o) => o !== g && o.name === next)) throw new ActionRefused(undefined, "conflict");
        g.name = next;
        return this.respond({});
      }
      case ACTION.nodeRename: {
        this.strict(input, ["node_id", "name"]);
        const node = typeof input.node_id === "number" ? this.nodes.get(input.node_id) : undefined;
        const next = this.name(input.name);
        if (!node) throw new ActionRefused(undefined, "not found");
        if ([...this.nodes.values()].some((o) => o !== node && o.name === next)) throw new ActionRefused(undefined, "conflict");
        // Grants and relays name hosts by name in this fake; the real server holds ids and needs none of this.
        const was = node.name, swap = (v: string): string => (v === was ? next : v);
        for (const g of this.grants) { g.from = swap(g.from); g.to = swap(g.to); if (g.via) g.via = swap(g.via); }
        for (const o of this.nodes.values()) if (o.via) o.via = swap(o.via);
        node.name = next;
        return this.respond({});
      }
      case ACTION.remove: {
        this.strict(input, ["name"]);
        const g = this.grants.find((o) => o.name === input.name);
        if (!g) throw new ActionRefused(undefined, "not found");
        this.grants = this.grants.filter((o) => o !== g);
        return this.respond({});
      }
      default: throw new ActionRefused(undefined, "invalid input");
    }
  }

  /** The answer carries the new revision; the event follows it (or comes first when `eventFirst`). */
  private respond(extra: Record<string, unknown>): Record<string, unknown> {
    this.revision += 1;
    const revision = this.revision;
    if (this.eventFirst) this.send(revision); else queueMicrotask(() => queueMicrotask(() => this.send(revision)));
    return { revision, ...extra };
  }
  private bump(): void { this.revision += 1; this.send(this.revision); }
  private send(revision: number): void {
    if (this.muted) return;
    for (const s of this.open.values()) s.onEvent({ type: "changed", revision });
  }
}
