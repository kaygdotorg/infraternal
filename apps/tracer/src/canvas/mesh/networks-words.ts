// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Every sentence the canvas says about networks (D197 M3, #580): a card's second line, the server's refusals in the owner's
 * words, the question before Revoke and the toasts after a change.
 *
 * It is a file of its own so the first-screen path (`networks.ts`: the shape of a network and the registry Settings
 * asks) does not carry wording that only the Mesh view, its API and the Networks window use; those load on demand (D188).
 *
 * TASTE: a sentence says what happens to the person, in plain words, with no ids or route numbers; a button is a verb.
 */
import type { MeshNetwork } from "./networks";

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
