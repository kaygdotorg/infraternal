/**
 * The canvas in the command palette (⌘K): go to a view, open Settings sections, canvas actions (lock, overview,
 * split, share), "Open shell on <host>" for every host the sessions adapter lists, and "Rename <host>" for the Mesh's hosts. Rows are computed each
 * time the palette opens, so they follow the state (the lock, the active window, the hosts that exist).
 *
 * Every row carries a `canvas:` action; the core screen forwards them as `tracer:canvas-action` events, which
 * this module handles. A row's `source` is "keyboard" when it was picked without the pointer, and keyboard
 * flights are the short version (camera.keyFlight).
 */
import { ICONS, withLockBadge } from "../../../../../packages/ui/src/icons";
import { shortcutLabel } from "../../../../../packages/ui/src/platform";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, ViewRec, WinRec } from "../context";
import { onDemand } from "../../on-demand";
import { recentRows } from "../recency";
import { windowLabel } from "../windows/label";
import { SETTINGS_SECTIONS } from "../views/settings";
import { ICON, SECTION_ICON, SESSION_ICON, viewIcon } from "../views/icons";
import { byFrecency } from "../sessions/inventory";
import { isTerminal } from "../views/body";
import { viewKeys } from "./viewlist";
import { bindingText } from "./shortcuts";

/** The rows of one view's windows, for the palette opened from the view's hover card ("All N windows", #121). */
export function viewWindowEntries(cx: Ctx, c: ViewRec): PaletteEntry[] {
  return [...c.wins.values()].map((rec) => {
    const m = rec.model;
    const [name, detail] = windowLabel(m, cx.adapters.inventory);
    return { group: c.view.name, glyph: "›_", icon: m.kind === "terminal" ? ICON.terminal : viewIcon(c.view.id), label: name, hint: detail, action: `canvas:win:${m.id}` };
  });
}

/** The windows a view's hover card lists: the five used most recently, filled in window order (see recency.ts). */
export function viewRecentWindows(cx: Ctx, c: ViewRec, n: number): WinRec[] {
  return recentRows(cx.state.recent.get(c.view.id), c.wins, n);
}

export function installPalette(cx: Ctx): () => void {
  const { core, signal, state, views } = cx;
  // The rows that act on a host (remove, rename, full access) come from an on-demand module the palette fetches as it is installed (D188).
  let hostRows: ((cx: Ctx) => PaletteEntry[]) | undefined;
  let hostRowsLoading = false;
  const loadHostRows = (): void => {
    if (hostRows || hostRowsLoading) return;
    hostRowsLoading = true;
    void onDemand(() => import("./palette-hosts.on-demand")).then((m) => { if (!signal.aborted) hostRows = m.hostEntries; }, () => { hostRowsLoading = false; });
  };
  loadHostRows(); // a small chunk, fetched as the canvas comes up, so the rows are there by the time anyone presses ⌘K
  const removeProvider = core.addPaletteProvider(() => {
    const out: PaletteEntry[] = [];
    [...views.values()].forEach((c, i) => {
      out.push({ group: "Views", glyph: "▦", icon: viewIcon(c.view.id), label: `Go to ${c.view.name}`, hint: `view · ${shortcutLabel(viewKeys(i))}`, action: `canvas:view:${c.view.id}` });
    });
    const settings = views.get("settings");
    if (settings) {
      out.push({ group: "Settings", glyph: "⚙", icon: viewIcon("settings"), label: "Settings", hint: "view · appearance · toolbar · shortcuts", action: "canvas:settings:appearance" });
      for (const sec of SETTINGS_SECTIONS) {
        if (!settings.wins.has(`s-${sec.id}`)) continue;
        out.push({ group: "Settings", glyph: "⚙", icon: SECTION_ICON[sec.id] ?? viewIcon("settings"), label: `Settings: ${sec.title}`, hint: "settings", action: `canvas:settings:${sec.id}` });
      }
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
    if (state.activeWin) out.push({ group: "Canvas", glyph: "▢", icon: ICONS.close, label: "Close window", hint: `the session keeps running · ${bindingText("close-window")}`, action: "canvas:close" });
    out.push({ group: "Canvas", glyph: "▦", icon: cx.inputLock.state ? withLockBadge(ICONS.terminal) : ICONS.terminal, label: cx.inputLock.state ? "Input lock off" : "Input lock on", hint: `the active window only · ${bindingText("input-lock")}`, action: "canvas:inputlock" });
    // Any host's shell by name. Keywords ride in the hint so "ssh", "terminal" and "console" find them.
    for (const host of cx.adapters.sessions.hosts()) {
      out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${host.name}`, hint: `terminal · ssh · console${host.online === false ? " · offline" : ""}`, action: `canvas:open:${host.id}` });
    }
    // Remove, rename and full-access rows for hosts: built by an on-demand module that loads at idle (D188).
    if (hostRows) out.push(...hostRows(cx)); else loadHostRows();
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
  });
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<import("./palette-actions.on-demand").CanvasAction>).detail;
    if (!detail?.action?.startsWith("canvas:")) return;
    if (detail.action.startsWith("canvas:openlink:")) {
      try { cx.adapters.activeTerminal?.()?.openLinkFromPalette?.(decodeURIComponent(detail.action.slice("canvas:openlink:".length))); } catch { /* A malformed palette action has no effect. */ }
      return;
    }
    const selected = state.activeWin;
    // Loading an action never delays host registration or the initial terminal; disposal fences a late chunk.
    void onDemand(() => import("./palette-actions.on-demand")).then((module) => {
      if (!signal.aborted) module.dispatchCanvasAction(cx, detail, selected);
    }, () => core.toast.show({ message: "The action couldn't load. Check your connection and try again.", tone: "error" }));
  };
  window.addEventListener("tracer:canvas-action", onAction, { signal });
  const offHosts = cx.adapters.sessions.onChange(() => core.refreshPalette());
  return () => { offHosts(); removeProvider(); };
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
