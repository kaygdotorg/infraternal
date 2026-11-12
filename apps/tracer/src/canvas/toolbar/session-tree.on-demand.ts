/**
 * The session list of the sidebar's Console section (D178, D188; on demand: it loads the first time the sidebar
 * shows the list). Each host is a caption and under it every session of the host, whether or not it has a window,
 * in frecency order: open (filled dot), detached (hollow dot and the detached icon, whose tooltip says "Detached") or
 * exited (hollow square and its exit code), with the activity mark of a detached one or the ✓ or ✗ of an exited one.
 * The marking itself is the shared `.ui-state-dot` and `.ui-mark` (packages/ui); this only says which leaf gets which.
 */
import type { BranchSection } from "../../../../../packages/ui/src/branched";
import type { Ctx } from "../context";
import { byFrecency, type SessionRecord } from "../sessions/inventory";
import { hostNote } from "../host-note";

declare const __CLUSTERS_PREVIEW__: boolean;
/**
 * Review flag `?marks=words` (preview builds only, compiled out of the product): an exited row says "finished" or
 * "failed, code 1" in words in place of the bare exit code, for the owner to compare with the ✓ 0 / ✗ 1 of today.
 */
const WORDS = typeof __CLUSTERS_PREVIEW__ !== "undefined" && __CLUSTERS_PREVIEW__ && new URLSearchParams(location.search).get("marks") === "words";

const leaf = (host: string, s: SessionRecord, renamable: boolean): BranchSection["leaves"][number] => {
  const code = s.exit?.code ?? 0;
  const mark = s.state === "exited" ? (code !== 0 ? "fail" : "ok") : s.activity;
  // The tick or cross on an exited row is the exit code in a picture; its tooltip says so in words.
  const markTip = s.state === "exited" ? (code !== 0 ? `Failed, exit code ${code}` : "Finished successfully, exit code 0") : undefined;
  const meta = s.state === "exited" ? (WORDS ? (code !== 0 ? `failed · ${code}` : "finished") : String(code)) : undefined;
  return { id: `s:${host}/${s.id}`, label: s.name, state: s.state, ...(mark ? { mark } : {}), ...(markTip ? { markTip } : {}), ...(meta ? { meta } : {}), ...(renamable ? { renamable: true, renameLabel: "Session name" } : {}) };
};

/** The id prefix of the row that unlocks host connections; the tree's selection handler runs the unlock for it. */
export const UNLOCK_ROW_PREFIX = "u:";

/**
 * Every admitted host, whether or not it has a session: a host that is offline or locked (or just has no shell open) must stay
 * listed, or it cannot be removed and its absence is unexplained (#500, J528). Hosts that have sessions come first, in the
 * inventory's order; the others follow in the host list's order. A host whose lock is what stops it carries the note
 * "locked" and an inline "Unlock to connect" row under it; any other offline host carries "offline".
 */
export const consoleLeaves = (cx: Ctx): BranchSection["leaves"] => {
  const inv = cx.adapters.inventory!;
  const admitted = cx.adapters.sessions.hosts().filter((h) => !h.state);
  const count = new Map<string, number>();
  for (const h of admitted) count.set(h.name, (count.get(h.name) ?? 0) + 1);
  const byName = new Map(admitted.map((h) => [h.name, h]));
  const renamable = inv.can?.rename !== false;
  const meshHosts = cx.adapters.mesh?.data().nodes;
  const names = [...new Set([...inv.hosts().filter((h) => byName.has(h)), ...admitted.map((h) => h.name)])];
  const rowsFor = (host: string, entry: (typeof admitted)[number], shared: boolean) => {
    const note = hostNote(cx, entry);
    // Two admitted hosts can carry one label (two logins on one machine are both named for its address): the later ones are
    // told apart by their login and addressed by their id, so no host is hidden behind another (#500, J528).
    const label = shared && entry.user ? `${entry.user}@${host}` : host;
    return [
      // A host is renamed through the Mesh (its node name), so only a host the Mesh knows can be.
      { id: shared ? `h:${entry.id}` : `h:${host}`, label, heading: true, ...(note ? { meta: note } : {}), ...(!shared && meshHosts?.has(host) && cx.mesh ? { renamable: true, renameLabel: "Host name" } : {}) },
      ...(note === "locked" ? [{ id: `${UNLOCK_ROW_PREFIX}${entry.id}`, label: "Unlock to connect", glyph: "◇" }] : []),
    ];
  };
  return names.flatMap((host) => {
    const same = admitted.filter((h) => h.name === host);
    const shared = (count.get(host) ?? 1) > 1;
    // Sessions are keyed by host label, so they list under the first host that carries it.
    return [
      ...same.flatMap((entry, i) => [...rowsFor(host, entry, shared), ...(i === 0 ? [...inv.list(host)].sort(byFrecency).map((sess) => leaf(host, sess, renamable)) : [])]),
    ];
  });
};
