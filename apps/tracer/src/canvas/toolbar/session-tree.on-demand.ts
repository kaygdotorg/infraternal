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

export const consoleLeaves = (cx: Ctx): BranchSection["leaves"] => {
  const inv = cx.adapters.inventory!;
  const allowed = new Set(cx.adapters.sessions.hosts().map((h) => h.name));
  const renamable = inv.can?.rename !== false;
  const meshHosts = cx.adapters.mesh?.data().nodes;
  return inv.hosts().filter((h) => allowed.has(h)).flatMap((host) => [
    // A host is renamed through the Mesh (its node name), so only a host the Mesh knows can be.
    { id: `h:${host}`, label: host, heading: true, ...(meshHosts?.has(host) && cx.mesh ? { renamable: true, renameLabel: "Host name" } : {}) },
    ...[...inv.list(host)].sort(byFrecency).map((s) => leaf(host, s, renamable)),
  ]);
};
