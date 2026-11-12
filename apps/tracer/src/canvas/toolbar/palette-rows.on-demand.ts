// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The rows the canvas puts in the command palette (⌘K): go to a view, open Settings sections, canvas actions (lock, overview,
 * split, share), "Open shell on <host>" for every host the sessions adapter lists, the host rows (remove, rename, full access)
 * and every session. They are computed each time the palette opens, so they follow the state (the lock, the active window,
 * the hosts that exist).
 *
 * The rows are text and icons that only matter once the palette is open, so this module loads on demand (D188, #322):
 * `palette.ts` fetches it as the canvas comes up (a few KB, so by the time anyone presses ⌘K it is there) and redraws an open
 * palette when it arrives.
 */
import { ICONS, withLockBadge } from "../../../../../packages/ui/src/icons";
import { shortcutLabel } from "../../../../../packages/ui/src/platform";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx } from "../context";
import { ICON, SESSION_ICON, viewIcon } from "../views/icons";
import { byFrecency } from "../sessions/inventory";
import { isTerminal } from "../views/body";
import { viewKeys } from "./viewlist";
import { bindingText } from "./shortcuts";
import { hostEntries } from "./palette-hosts.on-demand";
import { openShellEntries } from "../host-note";

/** Every row the canvas offers, for the state as it is now. */
export function canvasEntries(cx: Ctx): PaletteEntry[] {
  const { state, views } = cx;
    const out: PaletteEntry[] = [];
    [...views.values()].forEach((c, i) => {
      out.push({ group: "Views", glyph: "▦", icon: viewIcon(c.view.id), label: `Go to ${c.view.name}`, hint: `view · ${shortcutLabel(viewKeys(i))}`, action: `canvas:view:${c.view.id}` });
    });
    const settings = views.get("settings");
    const outline = cx.adapters.settings.outline;
    if (settings && outline) {
      // Settings as rows of windows (#304): the view, then every group, then every single setting that something stores (found by its
      // name, what it does and its technical names), each opening its own window.
      const rows = outline.rows();
      out.push({ group: "Settings", glyph: "⚙", icon: viewIcon("settings"), label: "Settings", hint: `view · ${rows.slice(0, 4).map((r) => r.title.toLowerCase()).join(" · ")}`, action: `canvas:settings:${rows[0]?.id ?? "appearance"}` });
      for (const e of outline.entries()) out.push({ group: "Settings", glyph: "⚙", icon: e.icon, label: e.label, hint: e.hint, action: e.action });
    }
    if (cx.sharing) out.push({ group: "Canvas", glyph: "⇪", icon: ICONS.next, label: "Share layout…", hint: "send views to a person or a group", action: "canvas:share" });
    if (views.get(state.currentView)?.view.team) out.push({ group: "Canvas", glyph: "⇪", icon: ICONS.unlock, label: "Unlink team layout to edit", hint: "keep your own copy", action: "canvas:unlink" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.canvas, label: "Canvas lock on", hint: `${state.canvasLock ? "on now · " : ""}${bindingText("canvas-lock")}`, action: "canvas:canvaslock:on" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.overview, label: "Canvas lock off", hint: "free pan and zoom, in place", action: "canvas:canvaslock:off" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.overview, label: "All views", hint: "fit every view · Esc", action: "canvas:overview" });
    if (state.activeWin && isTerminal(state.activeWin)) {
      const terminal = cx.adapters.activeTerminal?.();
      const targets = new Set<string>();
      for (const link of terminal?.linksOnScreen?.() ?? []) {
        if (!link.openable || targets.has(link.target)) continue;
        targets.add(link.target);
        out.push({
          group: "Links",
          glyph: "↗",
          label: `Open link: ${terminalLinkHostPart(link.target)}…`,
          hint: "terminal",
          action: `canvas:openlink:${encodeURIComponent(link.target)}`,
        });
      }
      out.push({ group: "Canvas", glyph: "▥", icon: ICONS.splitRight, label: "Split right", hint: `divides this window · ${bindingText("split-right")}`, action: "canvas:split:right" });
      out.push({ group: "Canvas", glyph: "▤", icon: ICONS.splitDown, label: "Split down", hint: `divides this window · ${bindingText("split-down")}`, action: "canvas:split:down" });
      out.push({ group: "Canvas", glyph: "▥", icon: ICONS.newRight, label: "New window right", hint: `full size, beside · ${bindingText("new-window-right")}`, action: "canvas:new:right" });
      out.push({ group: "Canvas", glyph: "▤", icon: ICONS.newBelow, label: "New window below", hint: `full size, under · ${bindingText("new-window-below")}`, action: "canvas:new:below" });
    }
    if (state.activeWin && cx.adapters.docs?.for(state.activeWin.model)) out.push({ group: "Canvas", glyph: "?", icon: ICON.help, label: "Read about this window", hint: `docs · ${bindingText("window-docs")}`, action: "canvas:windowdocs" });
    if (state.activeWin) out.push({ group: "Canvas", glyph: "▢", icon: ICONS.close, label: "Close window", hint: `the session keeps running · ${bindingText("close-window")}`, action: "canvas:close" });
    out.push({ group: "Canvas", glyph: "▦", icon: cx.inputLock.state ? withLockBadge(ICONS.terminal) : ICONS.terminal, label: cx.inputLock.state ? "Input lock off" : "Input lock on", hint: `the active window only · ${bindingText("input-lock")}`, action: "canvas:inputlock" });
    // Any host's shell by name. Keywords ride in the hint so "ssh", "terminal" and "console" find them.
    for (const row of openShellEntries(cx.adapters.sessions.hosts())) out.push({ ...row, icon: ICON.terminal });
    // Remove, rename and full-access rows for hosts.
    out.push(...hostEntries(cx));
    for (const row of cx.adapters.containers?.rows() ?? []) out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${row.name}`, hint: "container · terminal · console", action: `canvas:ctr:${row.name}` });
    // Every session on every host (D178), by name, with its state in the hint so "detached" or "exited" finds them.
    const inv = cx.adapters.inventory;
    if (inv?.status() === "ready") {
      if (state.activeWin && isTerminal(state.activeWin)) out.push({ group: "Sessions", glyph: "▤", icon: SESSION_ICON.sessions, label: "Sessions on this host", hint: "session manager", action: "canvas:sessions" });
      const allowed = new Set(cx.adapters.sessions.hosts().map((h) => h.name));
      for (const host of inv.hosts().filter((h) => allowed.has(h))) {
        for (const s of [...inv.list(host)].sort(byFrecency)) {
          const note = s.state === "exited" ? `${(s.exit?.code ?? 0) === 0 ? "✓" : "✗"} ${s.exit?.code ?? 0}` : s.state === "detached" ? `detached${s.activity === "output" ? " · new output" : s.activity === "ok" ? " · ✓" : s.activity === "fail" ? " · ✗" : ""}` : "open";
          out.push({ group: "Sessions", glyph: s.state === "open" ? "●" : s.state === "detached" ? "○" : "■", label: s.name, hint: `${host} · ${note}`, action: `canvas:session:${host}/${s.id}` });
        }
      }
    }
    return out;
}

function terminalLinkHostPart(target: string): string {
  try {
    const url = new URL(target);
    if (url.protocol === "mailto:") return url.pathname.split("@").at(-1) || url.pathname;
    return url.host || url.hostname;
  } catch {
    return target;
  }
}
