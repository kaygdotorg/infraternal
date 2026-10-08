/**
 * The real `MeshSource`: the Mesh API of #108 over the multiplexed connection (protocol.ts has the contract).
 *
 * State lives here and nowhere else: the last `mesh.list` and the edits in flight. The invariants:
 * - **One revision line.** `rev` is the server's revision of what this source shows. A `changed` event announces
 *   a newer revision and the source lists again (coalesced to one list per 200 ms; a pushed snapshot is applied
 *   as it is), so a missed event costs nothing: any later event, a reconnect or a retry brings everything up to date. A list older than what is on
 *   screen (an answer that raced an edit) is dropped.
 * - **Stable objects.** A grant or node keeps its object across updates (fields are changed in place), because
 *   the canvas holds arrows and cards by identity. The arrays only grow, shrink or reorder.
 * - **Optimistic edits.** An edit is applied at once and sent. If the server refuses it, or the socket drops, the
 *   grant goes back to what it was and `onFailure` says so; the server's answer is then written into the same
 *   object. A temporary id (`pending-n`) never leaves this module. While an edit is in flight no list is applied
 *   (it could not contain the edit yet and would flicker it away); one is fetched when the last edit settles.
 * - **Names are identity** (D180). A grant a person drags into being is named from its ends (`ops→build-01`,
 *   unique); when one of its ends moves and its name still said where it went, the name follows (a rename); a name
 *   a person chose is never touched.
 * - **Notifications are coalesced.** A burst of status changes becomes one `onChange` (80 ms), edits notify at
 *   once; nothing runs while the mesh is quiet.
 * - Positions are the canvas's: the server holds none. Pins arrive from the saved canvas document and leave
 *   through the canvas document (`pin` marks the node; the canvas saves it, D180).
 */
import type { Metrics } from "../layout/geometry";
import type { Grant, NodeModel } from "../model/types";
import { ACTION, ActionRefused, TOPIC, endpointJson, parseAnswer, parseEvent, parseSnapshot, type MeshTransport, type Snapshot, type WireAccess, type WireGrant, type WireNode } from "./protocol";
import { layoutMesh, tagNodeId, type Cluster } from "./layout";
import { grantLabel, type MeshLayout, type MeshSource, type MeshStatus } from "./source";

export interface MeshApiOptions {
  transport: MeshTransport;
  /** Positions the person pinned, from the saved canvas document. */
  pins?: Readonly<Record<string, { x: number; y: number }>>;
  /** Start in `ready` with this data instead of fetching (mockups that need a mesh at once). */
  prime?: Snapshot;
}

const RETRY_MS = [2_000, 5_000, 15_000, 30_000];
const REFRESH_COALESCE_MS = 200;
const NOTIFY_COALESCE_MS = 80;

/** What a grant is called when nobody named it: who may reach what. */
const derivedName = (from: string, to: string): string => grantLabel({ id: "", from, to });

export function createMeshApi(options: MeshApiOptions): MeshSource {
  const { transport } = options;
  const pins = new Map<string, { x: number; y: number }>(Object.entries(options.pins ?? {}));
  const listeners = new Set<() => void>();
  const failures = new Set<(message: string) => void>();
  let status: MeshStatus = "loading";
  let access: WireAccess = { view: false, manageGrants: false };
  let rev = 0;
  let nodes = new Map<string, WireNode>();
  let idOf = new Map<string, number>();
  let tags: Record<string, string[]> = {};
  let grants: Grant[] = [];
  const grantById = new Map<string, Grant>();
  let serial = 0;
  let generation = 0;
  let disposed = false;
  let retryTimer = 0, notifyTimer = 0, refreshTimer = 0, retryStep = 0;
  let notifyQueued = false;
  let inflight = 0, dirty = false, wanted = 0;
  let cache: { key: string; layout: MeshLayout } | undefined;
  let version = 0;

  const notify = (immediate: boolean): void => {
    version += 1;
    if (immediate) {
      window.clearTimeout(notifyTimer); notifyTimer = 0;
      if (!notifyQueued) { notifyQueued = true; queueMicrotask(() => { notifyQueued = false; for (const l of [...listeners]) l(); }); }
      return;
    }
    if (!notifyTimer) notifyTimer = window.setTimeout(() => { notifyTimer = 0; for (const l of [...listeners]) l(); }, NOTIFY_COALESCE_MS);
  };
  const fail = (message: string): void => { for (const l of [...failures]) l(message); };

  const toGrant = (w: WireGrant, into?: Grant): Grant => {
    const g = into ?? ({} as Grant);
    g.id = w.id; g.name = w.name; g.from = w.from; g.to = w.to;
    g.auto = w.name === derivedName(w.from, w.to);
    if (w.via) g.via = w.via; else delete g.via;
    if (w.both) g.both = true; else delete g.both;
    return g;
  };

  const apply = (s: Snapshot): void => {
    rev = s.rev; access = s.access;
    if (!access.view) { status = "unavailable"; notify(true); return; }
    nodes = new Map(s.nodes.map((n) => [n.name, n]));
    idOf = new Map(s.nodes.map((n) => [n.name, n.id]));
    tags = s.tags;
    const next = s.grants.map((w) => toGrant(w, grantById.get(w.id)));
    grantById.clear();
    for (const g of next) grantById.set(g.id, g);
    grants = next;
    status = "ready"; retryStep = 0;
    notify(true);
  };

  const refresh = (): void => {
    if (disposed) return;
    if (inflight > 0) { dirty = true; return; }
    const mine = ++generation;
    window.clearTimeout(retryTimer); retryTimer = 0;
    if (status === "error") status = "loading";
    transport.call(ACTION.list, {}).then((raw) => {
      if (disposed || mine !== generation) return;
      const snap = parseSnapshot(raw);
      if (!snap) { toError(); return; }
      if (snap.rev < rev) return; // an answer that raced a newer edit
      apply(snap);
      subscribe();
    }, (error: unknown) => {
      if (disposed || mine !== generation) return;
      // Refused (not allowed, or no such action here): the person has no Mesh. A server that could not answer is an error.
      if (error instanceof ActionRefused && error.reason !== "mesh unavailable") { status = "unavailable"; access = { view: false, manageGrants: false }; notify(true); return; }
      toError();
    });
  };
  const toError = (): void => {
    status = "error"; notify(true);
    const wait = RETRY_MS[Math.min(retryStep++, RETRY_MS.length - 1)]!;
    retryTimer = window.setTimeout(refresh, wait);
  };
  /** Something newer exists: list again soon (one list for a burst of events). */
  const invalidate = (to: number): void => {
    wanted = Math.max(wanted, to);
    if (refreshTimer) return;
    refreshTimer = window.setTimeout(() => { refreshTimer = 0; if (rev < wanted) refresh(); }, REFRESH_COALESCE_MS);
  };

  const onEvent = (raw: Record<string, unknown>): void => {
    const ev = parseEvent(raw);
    if (!ev || status === "loading") return;
    if (ev.kind === "changed") { if (ev.rev > rev) invalidate(ev.rev); return; }
    if (ev.kind === "snapshot") {
      // The server's own list, pushed: the same as asking, unless an edit is in flight or it is older than ours.
      if (inflight > 0) { dirty = true; return; }
      if (ev.snapshot.rev >= rev) apply(ev.snapshot);
      return;
    }
    // The subscription is over. Withdrawn view: the Mesh goes; anything else: ask again (and it will say why).
    if (ev.reason === "forbidden") { status = "unavailable"; access = { view: false, manageGrants: false }; notify(true); } else invalidate(rev + 1);
  };

  // Events are subscribed only after the server has answered a list: a server that does not serve the Mesh does not
  // know the subscription, and an unknown subscription closes the connection (so does everything else on it).
  let unsubscribe: (() => void) | undefined;
  const subscribe = (): void => { if (!unsubscribe) unsubscribe = transport.subscribe(TOPIC, onEvent, () => undefined); };
  // A reconnect (and the first connection) starts from a list: events sent while the socket was down are gone.
  let skipReady = Boolean(options.prime);
  const offReady = transport.onReady(() => { if (skipReady) { skipReady = false; return; } refresh(); });
  if (options.prime) { apply(options.prime); subscribe(); }

  // ---- layout -----------------------------------------------------------------------------------------------------
  const subOf = (n: WireNode): string => {
    if (n.state === "offline") return "offline";
    if (n.state === "behind") return "rules behind";
    const path = n.path === "relay" ? `via ${n.via ?? "relay"}` : n.path === "direct" ? "direct" : "";
    const rtt = n.rttMs === undefined ? "" : `${Math.round(n.rttMs)} ms`;
    return [path, rtt].filter(Boolean).join(" · ") || "online";
  };
  const objects = new Map<string, NodeModel>();
  const layout = (m: Metrics): MeshLayout => {
    const key = `${version}:${m.nodeW}x${m.nodeH}`;
    if (cache?.key === key) return cache.layout;
    const memberOf = new Map<string, string[]>();
    for (const [tag, members] of Object.entries(tags)) for (const h of members) (memberOf.get(h) ?? memberOf.set(h, []).get(h)!).push(tag);
    const placed = layoutMesh({
      hosts: [...nodes.keys()].map((id) => ({ id, tags: memberOf.get(id) ?? [] })),
      tags: Object.keys(tags),
      pins: Object.fromEntries(pins),
      nodeW: m.nodeW, nodeH: m.nodeH,
    });
    const out: NodeModel[] = [];
    for (const p of placed.nodes) {
      const w = p.kind === "host" ? nodes.get(p.id) : undefined;
      const members = p.kind === "tag" ? tags[p.id.slice(4)] ?? [] : [];
      const fields = p.kind === "host" && w
        ? { label: w.name, detail: w.address ?? (memberOf.get(w.name)?.map((t) => `tag:${t}`).join(", ") || "no tags"), sub: subOf(w), state: w.state, ...(w.os ? { os: w.os } : {}) }
        : { label: p.id, detail: `${members.length} member${members.length === 1 ? "" : "s"}`, sub: members.slice(0, 3).join(", ") };
      // The same object for the same node, so cards and arrows that hold it follow the new values.
      let n = objects.get(p.id);
      if (!n) { n = { id: p.id, kind: p.kind, x: p.x, y: p.y, ...fields } as NodeModel; objects.set(p.id, n); }
      else { Object.assign(n, fields); n.x = p.x; n.y = p.y; if (!("os" in fields)) delete n.os; if (!("state" in fields)) delete n.state; }
      if (p.pinned) n.pinned = true; else delete n.pinned;
      out.push(n);
    }
    const live = new Set(placed.nodes.map((p) => p.id));
    for (const id of [...objects.keys()]) if (!live.has(id)) objects.delete(id);
    const clusters: Cluster[] = placed.clusters;
    // With nothing to draw the view keeps a usable size for its loading, empty and error states.
    const result: MeshLayout = { nodes: out, size: out.length ? placed.size : { w: 880, h: 400 }, clusters };
    cache = { key, layout: result };
    return result;
  };

  // ---- edits ------------------------------------------------------------------------------------------------------
  const uniqueName = (base: string, except?: Grant): string => {
    const taken = new Set(grants.filter((g) => g !== except).map((g) => g.name));
    if (!taken.has(base)) return base;
    for (let i = 2; ; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
  };
  /** The server's answer advanced the revision by exactly this edit, or something else changed too and a list is due. */
  const advance = (to: number): void => { if (to === rev + 1) rev = to; else if (to > rev) dirty = true; };
  const settled = (): void => { if (inflight === 0 && dirty) { dirty = false; refresh(); } };
  /** Sends one edit. `undo` puts things back; `ok` writes the server's answer into the objects. */
  const send = (what: string, action: string, input: Record<string, unknown>, undo: () => void, ok: (answer: { rev: number; grantId?: string }) => void): void => {
    inflight += 1;
    transport.call(action, input).then((raw) => {
      if (disposed) return;
      const answer = parseAnswer(raw);
      if (!answer) { undo(); dirty = true; notify(true); }
      else { advance(answer.rev); ok(answer); }
      inflight -= 1; settled();
    }, (error: unknown) => {
      if (disposed) return;
      undo(); notify(true);
      fail(!(error instanceof ActionRefused) ? `Could not ${what}. Check the connection and try again.`
        : error.reason === "forbidden" ? `You are not allowed to ${what}.`
        : error.reason === "conflict" ? `Could not ${what}: that name or arrow already exists.`
        : `Could not ${what}. The mesh did not accept it.`);
      dirty = true; // what the server holds may differ from what was tried: list again once nothing is in flight
      inflight -= 1; settled();
    });
  };
  /** A grant's ends are known to the server only through ids: an unknown host cannot be an endpoint. */
  const end = (name: string): Record<string, unknown> | undefined => endpointJson(name, idOf);

  const source: MeshSource = {
    layout,
    grants: () => grants,
    tags: () => Object.fromEntries(Object.entries(tags).map(([k, v]) => [tagNodeId(k), v])),
    status: () => status,
    canView: () => access.view,
    canEdit: () => status !== "unavailable" && access.manageGrants,
    retry() { if (status === "error") { retryStep = 0; refresh(); } },
    addGrant(from, to) {
      const g: Grant = { id: `pending-${++serial}`, name: uniqueName(derivedName(from, to)), auto: true, from, to };
      grants.push(g); grantById.set(g.id, g);
      notify(true);
      const a = end(from), b = end(to);
      const drop = (): void => { grants = grants.filter((o) => o !== g); grantById.delete(g.id); };
      if (!a || !b) { queueMicrotask(() => { drop(); notify(true); fail(`Could not allow ${g.name}: the host is not in the mesh.`); }); return g; }
      send(`allow ${g.name}`, ACTION.create, { name: g.name, from: a, to: b, both_ways: false }, drop, (answer) => {
        grantById.delete(g.id);
        if (answer.grantId) g.id = answer.grantId;
        const twin = grantById.get(g.id);
        if (twin && twin !== g) { grants = grants.filter((o) => o !== g); } else grantById.set(g.id, g);
        notify(true);
      });
      return g;
    },
    moveGrant(grant, to) {
      const before = { from: grant.from, to: grant.to, name: grant.name };
      const follow = grant.auto === true;
      if (to.from) grant.from = to.from;
      if (to.to) grant.to = to.to;
      const target = end((to.to ?? to.from)!);
      const newName = follow ? uniqueName(derivedName(grant.from, grant.to), grant) : (grant.name ?? "");
      if (follow) grant.name = newName;
      notify(true);
      const back = (): void => { grant.from = before.from; grant.to = before.to; if (before.name !== undefined) grant.name = before.name; };
      if (!target) { queueMicrotask(() => { back(); notify(true); fail(`Could not move ${before.name ?? grant.id}: the host is not in the mesh.`); }); return; }
      send(`move ${before.name ?? grant.id}`, ACTION.move, { name: before.name ?? "", side: to.to ? "to" : "from", endpoint: target }, back, () => {
        if (!follow || newName === before.name) return;
        // The name still said where the grant went; it now says where it goes (a second, audited action).
        send(`rename ${before.name}`, ACTION.rename, { name: before.name ?? "", new_name: newName }, () => { grant.name = before.name!; grant.auto = false; }, () => { grant.auto = true; });
      });
    },
    renameGrant(grant, name) {
      const before = grant.name, auto = grant.auto;
      grant.name = name; grant.auto = name === derivedName(grant.from, grant.to);
      notify(true);
      send(`rename ${before ?? grant.id}`, ACTION.rename, { name: before ?? "", new_name: name }, () => { if (before !== undefined) grant.name = before; grant.auto = auto === true; }, () => undefined);
    },
    removeGrant(grant) {
      const at = grants.indexOf(grant);
      if (at < 0) return;
      grants = grants.filter((o) => o !== grant); grantById.delete(grant.id);
      notify(true);
      send(`remove ${grantLabel(grant)}`, ACTION.remove, { name: grant.name }, () => { grants.splice(Math.min(at, grants.length), 0, grant); grantById.set(grant.id, grant); }, () => undefined);
    },
    pin(id, x, y) { pins.set(id, { x: Math.round(x), y: Math.round(y) }); const n = objects.get(id); if (n) n.pinned = true; },
    onChange(l) { listeners.add(l); return () => { listeners.delete(l); }; },
    onFailure(l) { failures.add(l); return () => { failures.delete(l); }; },
    dispose() { disposed = true; window.clearTimeout(retryTimer); window.clearTimeout(notifyTimer); window.clearTimeout(refreshTimer); offReady(); unsubscribe?.(); listeners.clear(); failures.clear(); },
  };
  return source;
}
