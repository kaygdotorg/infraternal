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

const leaf = (host: string, s: SessionRecord): BranchSection["leaves"][number] => {
  const mark = s.state === "exited" ? ((s.exit?.code ?? 0) !== 0 ? "fail" : "ok") : s.activity;
  return { id: `s:${host}/${s.id}`, label: s.name, state: s.state, ...(mark ? { mark } : {}), ...(s.state === "exited" ? { meta: String(s.exit?.code ?? 0) } : {}) };
};

export const consoleLeaves = (cx: Ctx): BranchSection["leaves"] => {
  const inv = cx.adapters.inventory!;
  const allowed = new Set(cx.adapters.sessions.hosts().map((h) => h.name));
  return inv.hosts().filter((h) => allowed.has(h)).flatMap((host) => [
    { id: `h:${host}`, label: host, heading: true },
    ...[...inv.list(host)].sort(byFrecency).map((s) => leaf(host, s)),
  ]);
};
