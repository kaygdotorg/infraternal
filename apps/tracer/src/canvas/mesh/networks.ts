// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Subnet routes in the Mesh view (D197 M3, #580; mockup J1172, approved 2026-11-25): the networks a machine advertises,
 * and what the owner decided about each.
 *
 * A machine advertises a network it can reach (a LAN behind it). Nothing is routed until the owner approves it. An
 * approved network is a target for arrows, never their source: the machines on it are not part of the mesh. The owner
 * may also decline an advertisement; a declined one is remembered and stops asking (owner, 2026-11-25). Revoking an
 * approval deletes the arrows to it and puts the network back to waiting.
 *
 * This file holds the shape of one network as the canvas sees it, the interface the Mesh view and Settings use to read
 * and change networks (`RoutesSource`, implemented by the product's Mesh source in `api.ts`), the registry that tells
 * Settings whether there is one, and every sentence about networks.
 *
 * TASTE: a sentence says what happens to the person, in plain words, with no ids or route numbers; a button is a verb.
 */

/** Where a network stands: advertised and waiting, approved by the owner, or declined (and remembered). */
export type NetworkState = "pending" | "approved" | "declined";

/** One advertised, approved or declined network, as the owner sees it. */
export interface MeshNetwork {
  /** The id the canvas uses for its card and arrow ends: `net:<route id>`. */
  id: string;
  /** The server's identity of the route. A revoke gives the network a new one. */
  routeId: number;
  /** The machine that advertised it and carries the traffic into it, by id and by name. */
  nodeId: number;
  router: string;
  /** The network in its canonical form, `192.168.10.0/24`. */
  cidr: string;
  state: NetworkState;
  /** Whether the machine offers it now. An approved network it stopped offering is not routed until it does again. */
  advertised: boolean;
  /**
   * `false` (the default): the router gives what it forwards its own address, so the machines on the network need no
   * route back to the mesh. `true`: they see each machine's real mesh address, and need a route back through the router.
   */
  keepSource: boolean;
  /** Why approving it is refused (now, or by the owner's last Approve): a short line for the card, the whole sentence for the hover and the window. */
  refusal?: { short: string; sentence: string };
  /** A change the owner made is on its way to the server: shown at once, settled by the answer. */
  saving?: boolean;
}

/** The id arrows and cards use for a network, kept apart from host names and `tag:`. */
export const networkNodeId = (routeId: number): string => `net:${routeId}`;
/** Whether a node or arrow end id names a network. */
export const isNetworkId = (id: string): boolean => id.startsWith("net:");

/**
 * What the Mesh view and Settings may read and do. Every change is shown at once and settled by the server's answer: a
 * refusal or a lost connection puts the network back as it was and rejects with a sentence for the person.
 */
export interface RoutesSource {
  /** Every network the server lists, in a stable order: waiting first, then approved, then declined, each by address. */
  list(): readonly MeshNetwork[];
  /** The network with this canvas id. */
  get(id: string): MeshNetwork | undefined;
  /** How many arrows end on the network now (the revoke question says it). */
  arrowsTo(id: string): number;
  approve(id: string): Promise<void>;
  /** Turns an advertisement down; it is remembered, so the machine does not ask again. */
  decline(id: string): Promise<void>;
  /** Stops routing an approved network; the arrows that end on it are deleted and it waits again. */
  revoke(id: string): Promise<void>;
  setKeepSource(id: string, keep: boolean): Promise<void>;
  onChange(listener: () => void): () => void;
}

/** The registered source and who wants to know when it comes and goes (Settings shows the Networks window only while one is there). */
let current: RoutesSource | undefined;
/** Who is told when a routes source comes or goes (`onRoutesSource`). */
const watchers = new Set<() => void>();
/** The routes of the server, when it lists them to this person (the owner), or none. */
export const routesSource = (): RoutesSource | undefined => current;
/** Registers (or removes, with `undefined`) the source of networks, and tells the watchers when that changes. */
export function setRoutesSource(source: RoutesSource | undefined): void {
  if (current === source) return;
  current = source;
  for (const w of [...watchers]) w();
}
/** Calls `listener` whenever a source is registered or removed. Returns the function that stops it. */
export function onRoutesSource(listener: () => void): () => void { watchers.add(listener); return () => { watchers.delete(listener); }; }

/** The words a card, a chip or a sentence uses for an arrow end that is a network: its address. */
export function networkLabel(id: string): string {
  return current?.get(id)?.cidr ?? "a network";
}

/** Whether the Mesh view draws a network's card: waiting or approved. A declined one lives only in Settings. */
export const drawnInMesh = (n: MeshNetwork): boolean => n.state === "approved" || (n.state === "pending" && n.advertised);

/** What a card says under the network's address: who carries it, and whether it is waiting. */
export function networkDetail(n: MeshNetwork): string {
  return n.state === "approved" ? `through ${n.router}` : `advertised by ${n.router}`;
}

/** The second line of a network's card: the state, and what the machines on it will see. */
export function networkSub(n: MeshNetwork): string {
  if (n.state === "pending") return n.refusal ? n.refusal.short : "Waiting for approval";
  if (n.state === "declined") return "Declined";
  if (!n.advertised) return `${n.router} stopped offering it`;
  return n.keepSource ? "Keeps each machine's own address" : `Appears as ${n.router}`;
}

/** Text of the server's refusal: a full stop at the end and a capital at the start. */
const sentence = (text: string): string => {
  const t = text.trim();
  if (!t) return "The server did not approve it.";
  return t[0]!.toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? "" : ".");
};

/**
 * The server's reason for refusing an approval, in the owner's words: a short line for the card and a sentence for the
 * hover and the window. The server names the clashing route by number ("(route 4)"); a person knows networks by address,
 * so the number goes. Reasons the canvas does not recognise are shown as the server wrote them.
 */
export function refusalWords(reason: string): { short: string; sentence: string } {
  const overlap = /^(\S+) overlaps (\S+), which is already approved/.exec(reason);
  if (overlap) return { short: `Overlaps ${overlap[2]}`, sentence: overlapRefusal(overlap[1]!, overlap[2]!) };
  const mesh = /^(\S+) overlaps the mesh's own range (\S+?);/.exec(reason);
  if (mesh) return { short: "Overlaps the mesh", sentence: `${mesh[1]} overlaps the mesh's own addresses (${mesh[2]}). Have the machine advertise a network outside them.` };
  const clean = reason.replace(/ \(route \d+\)/g, "");
  if (/is an IPv6 network/.test(clean)) return { short: "IPv6 is not routed yet", sentence: sentence(clean) };
  if (/is every address/.test(clean)) return { short: "That is every address", sentence: sentence(clean) };
  if (/is never routed/.test(clean)) return { short: "Never routed", sentence: sentence(clean) };
  if (/no longer advertises/.test(clean)) return { short: "No longer offered", sentence: sentence(clean) };
  return { short: "Cannot be approved", sentence: sentence(clean) };
}

/** The sentence when two networks overlap (the server's own refusal, in plain words: no route numbers). */
export const overlapRefusal = (cidr: string, approved: string): string =>
  `${cidr} overlaps ${approved}, which is already approved. Revoke that one first, or have the machine advertise a network that does not overlap.`;

/** The question before Revoke: names the network, says what stops, and that the arrows do not come back (D295: say what is lost). */
export function revokeConfirm(n: Pick<MeshNetwork, "cidr" | "router">, arrows: number): { title: string; effect: string; confirmLabel: string; cancelLabel: string } {
  const lost = arrows === 0 ? "No arrow ends on it." : arrows === 1 ? "The 1 arrow that ends on it is deleted." : `The ${arrows} arrows that end on it are deleted.`;
  return {
    title: `Stop routing ${n.cidr}?`,
    effect: `Machines can no longer reach it through ${n.router}. ${lost} Approving it again does not bring them back.`,
    confirmLabel: "Revoke",
    cancelLabel: "Keep it",
  };
}

/** The toast after an approval: what arrows can do now. */
export const approvedToast = (cidr: string): string => `${cidr} is approved. Draw an arrow to it to let a machine reach it.`;
/** The toast after a decline: it will not ask again. */
export const declinedToast = (cidr: string, router: string): string => `${cidr} is declined. ${router} will not ask about it again.`;
/** The toast after a revoke. */
export const revokedToast = (cidr: string): string => `${cidr} is no longer routed. It waits for approval again.`;
