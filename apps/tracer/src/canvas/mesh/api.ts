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
 * - **Subnet routes ride on the same revision line** (D197 M3). After every applied list the source also lists the
 *   routes (`mesh.route.list`, one call in flight, a second asked for while it runs is run once after it), when the
 *   person may manage access. Only the owner may list them: anyone else is refused once and the source stops asking,
 *   so it shows no networks. Approve, decline,
 *   revoke and keep-source are optimistic like grant edits: the network changes at once (and a revoke takes its arrows
 *   off the screen), the server's answer settles it, and a refusal or a lost connection puts everything back and rejects
 *   with a sentence. A route list is not applied while a route change is in flight, for the same reason as grants.
 * - Positions are the canvas's: the server holds none. Pins arrive from the saved canvas document and leave
 *   through the canvas document (`pin` marks the node; the canvas saves it, D180).
 */
import type { Grant } from "../model/types";
import { MeshClient, type MeshSubscriptionEvent } from "../../../../../packages/protocol/src/mesh";
import { ACTION, ActionRefused, endpointJson, parseAnswer, parseRouteAnswer, parseRoutes, parseSnapshot, type MeshTransport, type Snapshot, type WireAccess, type WireGrant, type WireNode, type WireRoute } from "./protocol";
import { networkNodeId, setRoutesSource, routesSource, type MeshNetwork, type RoutesSource } from "./networks";
import { drawnInMesh, refusalWords } from "./networks-words";
import { derivedGrantName, endName, tagNodeId, type MeshSource, type MeshStatus } from "./source";

export interface MeshApiOptions {
  transport: MeshTransport;
  /** Positions the person pinned, from the saved canvas document. */
  pins?: Readonly<Record<string, { x: number; y: number }>>;
  /** Start in `ready` with this data instead of fetching (mockups that need a mesh at once). */
  prime?: Snapshot;
}

const RETRY_MS = [2_000, 5_000, 15_000, 30_000];
const NOTIFY_COALESCE_MS = 80;

/** What a grant is called when nobody named it: who may reach what. */
const derivedName = derivedGrantName;

/**
 * Makes the product's Mesh source over `options.transport`: the mesh, the grants and (for the owner) the subnet routes, kept
 * on one revision line, with optimistic edits that the server's answers settle (the invariants are in the module comment).
 */
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
  let generation = 0, publication = 0;
  let disposed = false;
  let retryTimer = 0, notifyTimer = 0, retryStep = 0;
  let notifyQueued = false;
  let inflight = 0, dirty = false;
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
    // A pushed recovery supersedes pending failures; successful replies still
    // follow the server revision, so a newer retry snapshot can advance it.
    publication += 1;
    if (retryTimer) { window.clearTimeout(retryTimer); retryTimer = 0; }
    rev = s.rev; access = s.access;
    if (!access.view) { generation += 1; status = "unavailable"; notify(true); return; }
    // A node that left the mesh takes its pin with it: a pin a drag wrote for it before it went must not outlive it.
    const present = new Set(s.nodes.map((n) => n.name));
    for (const name of nodes.keys()) if (!present.has(name)) pins.delete(name);
    nodes = new Map(s.nodes.map((n) => [n.name, n]));
    idOf = new Map(s.nodes.map((n) => [n.name, n.id]));
    tags = s.tags;
    const next = s.grants.map((w) => toGrant(w, grantById.get(w.id)));
    grantById.clear();
    for (const g of next) grantById.set(g.id, g);
    grants = next;
    status = "ready"; retryStep = 0;
    notify(true);
    listRoutes();
  };

  /** Lists the whole mesh (the client follows the server's pages) and shows it. */
  const refresh = (): void => {
    if (disposed) return;
    if (inflight > 0) { dirty = true; return; }
    const mine = ++generation, published = publication;
    window.clearTimeout(retryTimer); retryTimer = 0;
    if (status === "error") status = "loading";
    client.list().then((raw) => {
      if (disposed || mine !== generation) return;
      const snap = parseSnapshot(raw);
      if (!snap) { if (published === publication) toError(); return; }
      // Expiry can change liveness without advancing the stored revision.
      // On a revision tie, retain the state published after this request began.
      if (snap.rev < rev || (snap.rev === rev && published !== publication)) return;
      apply(snap);
      watch();
    }, (error: unknown) => {
      if (disposed || mine !== generation || published !== publication) return;
      // Refused (not allowed, or no such action here): the person has no Mesh. A server that could not answer is an error.
      if (error instanceof ActionRefused && error.reason !== "mesh unavailable") { withdraw(); return; }
      toError();
    });
  };
  const withdraw = (): void => {
    // Withdrawal has no snapshot revision, so invalidate pending requests too.
    generation += 1;
    window.clearTimeout(retryTimer); retryTimer = 0;
    status = "unavailable"; access = { view: false, manageGrants: false }; notify(true);
  };
  const toError = (): void => {
    status = "error"; notify(true);
    window.clearTimeout(retryTimer);
    const wait = RETRY_MS[Math.min(retryStep++, RETRY_MS.length - 1)]!;
    retryTimer = window.setTimeout(refresh, wait);
  };

  // ---- subnet routes (D197 M3) ---------------------------------------------------------------------------------------
  /** `unknown` until the server answers a route list, `on` while it lists them to this person, `off` once it refused. */
  let routesState: "unknown" | "on" | "off" = "unknown";
  let networks: MeshNetwork[] = [];
  const networkById = new Map<string, MeshNetwork>();
  /** What `data()` hands the Mesh view: the networks it draws, rebuilt only when a network changes. */
  let drawn: readonly MeshNetwork[] = [];
  let routesListing = false, routesAgain = false, routeInflight = 0;
  const RANK = { pending: 0, approved: 1, declined: 2 } as const;
  const networksChanged = (): void => {
    networks.sort((a, b) => RANK[a.state] - RANK[b.state] || (a.cidr < b.cidr ? -1 : a.cidr > b.cidr ? 1 : a.routeId - b.routeId));
    drawn = networks.filter(drawnInMesh);
    for (const l of [...routeListeners]) l();
    notify(true);
  };
  /** The server's list, written into the same objects (cards and the Networks window hold them by identity). */
  const applyRoutes = (wire: readonly WireRoute[]): void => {
    const next: MeshNetwork[] = [];
    const seen = new Set<string>();
    for (const w of wire) {
      const id = networkNodeId(w.id);
      if (seen.has(id)) continue;
      seen.add(id);
      const n = networkById.get(id) ?? ({ id } as MeshNetwork);
      n.routeId = w.id; n.nodeId = w.nodeId; n.router = w.router; n.cidr = w.cidr; n.state = w.state;
      n.advertised = w.advertised; n.keepSource = !w.masquerade;
      if (w.state === "pending" && w.refused) n.refusal = refusalWords(w.refused); else delete n.refusal;
      delete n.saving;
      next.push(n);
    }
    networkById.clear();
    for (const n of next) networkById.set(n.id, n);
    networks = next;
    networksChanged();
  };
  /** Lists the routes once; a list asked for while one runs or a change is in flight runs after it. */
  const listRoutes = (): void => {
    // Only someone who may change who reaches what can be the owner, so nobody else is even asked about (one call fewer per list).
    if (disposed || routesState === "off" || !access.view || !access.manageGrants) return;
    if (routesListing || routeInflight > 0) { routesAgain = true; return; }
    routesListing = true;
    transport.call(ACTION.routes, {}).then((raw) => {
      routesListing = false;
      if (disposed) return;
      const wire = parseRoutes(raw);
      if (wire && routeInflight === 0) {
        applyRoutes(wire);
        if (routesState !== "on") { routesState = "on"; setRoutesSource(routes); }
      }
      if (routesAgain) { routesAgain = false; listRoutes(); }
    }, (error: unknown) => {
      routesListing = false;
      if (disposed) return;
      // Not the owner (or a server without subnet routes): no networks, and no more asking. A lost answer waits for the next list.
      if (error instanceof ActionRefused) {
        routesState = "off";
        networks = []; networkById.clear();
        if (routesSource() === routes) setRoutesSource(undefined);
        networksChanged();
        return;
      }
      if (routesAgain) { routesAgain = false; listRoutes(); }
    });
  };
  /** What a refused or failed route change says. */
  const routeFailure = (what: string, error: unknown): string => {
    if (!(error instanceof ActionRefused)) return `Could not ${what}. Check your connection and try again.`;
    switch (error.reason) {
      case "forbidden": return `Could not ${what}. Only the server's owner can, with a fresh passkey check. Sign in again and try once more.`;
      case "not found": return `Could not ${what}: the machine no longer offers it, or it changed. The list is up to date again.`;
      case "invalid input": return `Could not ${what}: the server did not accept those details.`;
      default: return `Could not ${what}. The mesh is busy. Try again in a moment.`;
    }
  };
  /**
   * Sends one route change: `change` shows it at once, `undo` puts it back. A refusal (`{state:"refused"}`) or an error
   * undoes it and rejects with the sentence to show; either way the routes are listed again once nothing is in flight.
   */
  const routeChange = (n: MeshNetwork, what: string, action: string, input: Record<string, unknown>, change: () => void, undo: () => void): Promise<void> => {
    routeInflight += 1;
    change();
    n.saving = true;
    networksChanged();
    const settle = (): void => { routeInflight -= 1; delete n.saving; if (routeInflight === 0) { routesAgain = false; listRoutes(); } };
    return transport.call(action, input).then((raw) => {
      if (disposed) return;
      const answer = parseRouteAnswer(raw);
      if (answer?.ok) { settle(); networksChanged(); return; }
      undo();
      if (answer) n.refusal = refusalWords(answer.reason);
      settle(); networksChanged();
      throw new Error(answer ? n.refusal!.sentence : `Could not ${what}. The server's answer was not understood; try again in a moment.`);
    }, (error: unknown) => {
      if (disposed) return;
      undo(); settle(); networksChanged();
      throw new Error(routeFailure(what, error));
    });
  };
  const routeListeners = new Set<() => void>();
  const known = (id: string): MeshNetwork => {
    const n = networkById.get(id);
    if (!n) throw new Error("That network is no longer listed.");
    return n;
  };
  const routes: RoutesSource = {
    list: () => networks,
    get: (id) => networkById.get(id),
    arrowsTo: (id) => grants.reduce((k, g) => k + (g.to === id ? 1 : 0), 0),
    approve(id) {
      let n: MeshNetwork;
      try { n = known(id); } catch (e) { return Promise.reject(e as Error); }
      if (n.state === "approved") return Promise.resolve();
      const before = { state: n.state, refusal: n.refusal };
      return routeChange(n, `approve ${n.cidr}`, ACTION.routeApprove, { node_id: n.nodeId, network: n.cidr, masquerade: !n.keepSource },
        () => { n.state = "approved"; delete n.refusal; },
        () => { n.state = before.state; if (before.refusal) n.refusal = before.refusal; });
    },
    decline(id) {
      let n: MeshNetwork;
      try { n = known(id); } catch (e) { return Promise.reject(e as Error); }
      if (n.state !== "pending") return Promise.resolve();
      return routeChange(n, `decline ${n.cidr}`, ACTION.routeDecline, { route_id: n.routeId }, () => { n.state = "declined"; }, () => { n.state = "pending"; });
    },
    revoke(id) {
      let n: MeshNetwork;
      try { n = known(id); } catch (e) { return Promise.reject(e as Error); }
      if (n.state !== "approved") return Promise.resolve();
      // The arrows to it go at once, as they do on the server; an undo brings the same objects back in their places.
      const kept = grants;
      return routeChange(n, `stop routing ${n.cidr}`, ACTION.routeRevoke, { route_id: n.routeId },
        () => { n.state = "pending"; grants = grants.filter((g) => g.to !== id); for (const g of kept) if (g.to === id) grantById.delete(g.id); },
        () => { n.state = "approved"; grants = kept; for (const g of kept) grantById.set(g.id, g); });
    },
    setKeepSource(id, keep) {
      let n: MeshNetwork;
      try { n = known(id); } catch (e) { return Promise.reject(e as Error); }
      if (n.state !== "approved" || n.keepSource === keep) return Promise.resolve();
      return routeChange(n, keep ? `keep each machine's address on ${n.cidr}` : `show ${n.router}'s address on ${n.cidr}`, ACTION.routeApprove,
        { node_id: n.nodeId, network: n.cidr, masquerade: !keep }, () => { n.keepSource = keep; }, () => { n.keepSource = !keep; });
    },
    onChange(l) { routeListeners.add(l); return () => { routeListeners.delete(l); }; },
  };

  // The live part is the protocol client's: it follows the server's pages, keeps one revision line, drops answers a newer
  // one supersedes, and lists again when told something changed. It is started only after the server has answered a
  // list: a server that does not serve the Mesh does not know the subscription, and an unknown subscription closes the
  // connection (so does everything else on it).
  const client = new MeshClient({
    call: (action, input) => transport.call(action, input as Record<string, unknown>) as Promise<never>,
    subscribe: (filter, listener) => transport.subscribe(filter.topic, (raw) => listener(raw as unknown as MeshSubscriptionEvent), () => undefined),
  });
  let stopWatch: (() => void) | undefined;
  const watch = (): void => {
    if (stopWatch || disposed) return;
    let ended = false;
    const release = client.watch({}, (ev) => {
      if (disposed) return;
      if (ev.type === "error") {
        // A local refresh failure leaves the server watch installed. Keep it:
        // the frozen wire has replacement subscriptions, but no unsubscribe.
        if (ev.subscriptionActive) { toError(); return; }
        // The server ended the subscription. A withdrawn view: the Mesh goes. Anything else: ask again, with a new watch.
        // A server withdrawal ends this watch. Release the client handle and
        // pending page work before retry installs its replacement (#229).
        ended = true;
        const stop = stopWatch;
        stopWatch = undefined;
        stop?.();
        if (ev.error === "forbidden") withdraw(); else toError();
        return;
      }
      const snap = parseSnapshot(ev.snapshot);
      if (!snap) return;
      // The server's own list, pushed: the same as asking, unless an edit is in flight or it is older than ours.
      if (inflight > 0) { dirty = true; return; }
      if (snap.rev >= rev) apply(snap);
    });
    // Refusal may arrive inside subscribe, before its release handle exists.
    if (ended) release(); else stopWatch = release;
  };
  // The first connection and every reconnect (a terminal is attached): start from a list when nothing is live; a live
  // watch is subscribed again by the connection and answers with its own snapshot.
  let skipReady = Boolean(options.prime);
  const offReady = transport.onReady(() => { if (skipReady) { skipReady = false; return; } if (!stopWatch) refresh(); });
  if (options.prime) { apply(options.prime); watch(); }

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
      fail(!(error instanceof ActionRefused) ? `Could not ${what}. Check your connection and try again.`
        // Changing or ending access also needs a recent passkey check; the server answers both "no" and "check first" alike.
        : error.reason === "forbidden" ? `Could not ${what}. Your account may not allow it, or it needs a fresh passkey check first. Sign in again and try once more.`
        : error.reason === "conflict" ? `Could not ${what}: that already exists.`
        : error.reason === "reserved for the server" ? `Could not ${what}: that name belongs to the server.`
        : error.reason === "not found" ? `Could not ${what}: it is no longer there.`
        : error.reason === "invalid input" ? `Could not ${what}: the server did not accept those details.`
        : `Could not ${what}. The mesh is busy. Try again in a moment.`);
      dirty = true; // what the server holds may differ from what was tried: list again once nothing is in flight
      inflight -= 1; settled();
    });
  };
  /**
   * A host's name is its identity on the canvas (grant ends, `via`, tag members, pins), so a rename the server accepted
   * is written through all of them at once, in place (objects stay, so cards and arrows keep their identity). The
   * next list says the same; this only spares the screen a second with a name that is no longer true.
   */
  const rekeyNode = (from: string, to: string): void => {
    const node = nodes.get(from);
    if (!node || from === to) return;
    node.name = to;
    nodes = new Map([...nodes].map(([k, v]) => [k === from ? to : k, v] as const));
    idOf = new Map([...idOf].map(([k, v]) => [k === from ? to : k, v] as const));
    const swap = (v: string): string => (v === from ? to : v);
    for (const n of nodes.values()) if (n.via === from) n.via = to;
    tags = Object.fromEntries(Object.entries(tags).map(([tag, members]) => [tag, members.map(swap)]));
    for (const g of grants) {
      g.from = swap(g.from); g.to = swap(g.to);
      if (g.via === from) g.via = to;
      g.auto = g.name === derivedName(g.from, g.to);
    }
    const pin = pins.get(from);
    if (pin) { pins.delete(from); pins.set(to, pin); }
  };
  /** What a refused rename says, in plain words: the reason first, never the server's own code. */
  const nodeRenameRefusal = (from: string, to: string, error: unknown): string => {
    const head = `Could not rename ${from}`;
    if (!(error instanceof ActionRefused)) return `${head}. Check your connection and try again.`;
    switch (error.reason) {
      case "forbidden": return `${head}: you are not allowed to rename hosts.`;
      case "conflict": return `${head}: another host is already called ${to}.`;
      case "reserved for the server": return `${head}: ${to} is the name of the server.`;
      case "not found": return `${head}: it is no longer in the mesh.`;
      case "invalid input": return `${head}: ${to} is not a name the server accepts.`;
      default: return `${head}. The mesh is busy. Try again in a moment.`;
    }
  };
  /** A grant's ends are known to the server only through ids: an unknown host cannot be an endpoint. */
  const end = (name: string): Record<string, unknown> | undefined => endpointJson(name, idOf);

  const source: MeshSource = {
    data: () => ({ version, nodes, tags, pins, networks: drawn }),
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
      if (!a || !b) { queueMicrotask(() => { drop(); notify(true); fail(`Could not let ${endName(from)} reach ${endName(to)}: that host is no longer in the mesh.`); }); return g; }
      send(`let ${endName(from)} reach ${endName(to)}`, ACTION.create, { name: g.name, from: a, to: b, both_ways: false }, drop, (answer) => {
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
      const moving = to.to ? `change who ${endName(before.from)} can reach` : `change who can reach ${endName(before.to)}`;
      if (!target) { queueMicrotask(() => { back(); notify(true); fail(`Could not ${moving}: that host is no longer in the mesh.`); }); return; }
      send(moving, ACTION.move, { name: before.name ?? "", side: to.to ? "to" : "from", endpoint: target }, back, () => {
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
      send(`stop ${endName(grant.from)} reaching ${endName(grant.to)}`, ACTION.remove, { name: grant.name }, () => { grants.splice(Math.min(at, grants.length), 0, grant); grantById.set(grant.id, grant); }, () => undefined);
    },
    renameNode(name, newName) {
      const wanted = newName.trim();
      const id = idOf.get(name);
      return new Promise<void>((resolve, reject) => {
        if (id === undefined) { reject(new Error(`Could not rename ${name}: it is no longer in the mesh.`)); return; }
        inflight += 1;
        transport.call(ACTION.nodeRename, { node_id: id, name: wanted }).then((raw) => {
          if (disposed) return;
          const answer = parseAnswer(raw);
          if (!answer) { dirty = true; reject(new Error(`Could not rename ${name}. The server's answer was not understood; try again in a moment.`)); }
          else { rekeyNode(name, wanted); advance(answer.rev); notify(true); resolve(); }
          inflight -= 1; settled();
        }, (error: unknown) => {
          if (disposed) return;
          reject(new Error(nodeRenameRefusal(name, wanted, error)));
          dirty = true; // what the server holds may differ from what was tried
          inflight -= 1; settled();
        });
      });
    },
    pin(id, x, y) { pins.set(id, { x: Math.round(x), y: Math.round(y) }); },
    onChange(l) { listeners.add(l); return () => { listeners.delete(l); }; },
    onFailure(l) { failures.add(l); return () => { failures.delete(l); }; },
    dispose() { disposed = true; if (routesSource() === routes) setRoutesSource(undefined); routeListeners.clear(); window.clearTimeout(retryTimer); window.clearTimeout(notifyTimer); offReady(); stopWatch?.(); listeners.clear(); failures.clear(); },
  };
  return source;
}
