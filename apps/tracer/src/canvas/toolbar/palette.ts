/**
 * The canvas in the command palette (⌘K): go to a view, open Settings sections, canvas actions (lock, overview,
 * split, share), and "Open shell on <host>" for every host the sessions adapter lists. Rows are computed each
 * time the palette opens, so they follow the state (the lock, the active window, the hosts that exist).
 *
 * Every row carries a `canvas:` action; the core screen forwards them as `tracer:canvas-action` events, which
 * this module handles. A row's `source` is "keyboard" when it was picked without the pointer, and keyboard
 * flights are the short version (camera.keyFlight).
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import { shortcutLabel } from "../../../../../packages/ui/src/platform";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx } from "../context";
import type { ViewId } from "../model/types";
import { SETTINGS_SECTIONS } from "../views/settings";
import { ICON, SECTION_ICON, viewIcon } from "../views/icons";
import { isTerminal } from "../views/body";
import { viewKeys } from "./viewlist";
import { bindingText } from "./shortcuts";

/** Flies to a Settings window (canvas-locked, snapped to its column). */
export function openSettings(cx: Ctx, section: string): void {
  const c = cx.views.get("settings");
  const rec = c?.wins.get(`s-${section}`) ?? [...(c?.wins.values() ?? [])][0];
  if (!rec) return;
  cx.win.setActive(rec);
  cx.nav.focusWindow(rec);
}

export function installPalette(cx: Ctx): () => void {
  const { core, signal, state, views } = cx;
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
        out.push({ group: "Settings", glyph: "⚙", icon: SECTION_ICON[sec.id] ?? viewIcon("settings"), label: `Settings → ${sec.title}`, hint: "settings", action: `canvas:settings:${sec.id}` });
      }
    }
    if (cx.sharing) out.push({ group: "Canvas", glyph: "⇪", icon: ICONS.next, label: "Share layout…", hint: "send views to a person or a group", action: "canvas:share" });
    if (views.get(state.currentView)?.view.team) out.push({ group: "Canvas", glyph: "⇪", icon: ICONS.unlock, label: "Unlink team layout to edit", hint: "keep your own copy", action: "canvas:unlink" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.snap, label: "Canvas lock on", hint: `${state.canvasLock ? "on now · " : ""}${bindingText("canvas-lock")}`, action: "canvas:canvaslock:on" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.overview, label: "Canvas lock off", hint: "free pan and zoom, in place", action: "canvas:canvaslock:off" });
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.overview, label: "All views", hint: "fit every view · Esc", action: "canvas:overview" });
    if (state.activeWin && isTerminal(state.activeWin)) {
      out.push({ group: "Canvas", glyph: "▥", icon: ICONS.splitRight, label: "Split right", hint: `new window beside · ${bindingText("split-right")}`, action: "canvas:split:right" });
      out.push({ group: "Canvas", glyph: "▤", icon: ICONS.splitDown, label: "Split down", hint: `new window below · ${bindingText("split-down")}`, action: "canvas:split:down" });
    }
    out.push({ group: "Canvas", glyph: "▦", icon: ICONS.lock, label: cx.inputLock.state ? "Input lock off" : "Input lock on", hint: `the active window only · ${bindingText("input-lock")}`, action: "canvas:inputlock" });
    // Any session by name. Keywords ride in the hint so "ssh", "terminal" and "console" find them.
    for (const host of cx.adapters.sessions.hosts()) {
      out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${host.name}`, hint: "terminal · ssh · console", action: `canvas:open:${host.name}` });
    }
    for (const row of cx.adapters.containers?.rows() ?? []) out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${row.name}`, hint: "container · terminal · console", action: `canvas:ctr:${row.name}` });
    return out;
  });
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: string; source?: string }>).detail;
    const [, kind, value] = (detail?.action ?? "").split(":");
    const active = state.activeWin;
    if (kind === "view" && value) { if (detail?.source === "keyboard") cx.camera.keyFlight(() => cx.nav.flyView(value as ViewId)); else cx.nav.flyView(value as ViewId); }
    else if (kind === "overview") cx.nav.showOverview();
    else if (kind === "settings") openSettings(cx, value ?? "appearance");
    else if (kind === "share") void cx.sharing?.open();
    else if (kind === "unlink") cx.sharing?.unlinkCurrent();
    else if (kind === "split") { if (active && isTerminal(active)) void cx.win.split(active, value === "right" ? "right" : "down"); }
    else if (kind === "canvaslock") cx.nav.setCanvasLock(value === "on");
    else if (kind === "inputlock") cx.inputLock.toggle();
    else if (kind === "open" && value) cx.win.open(value);
    else if (kind === "ctr" && value && cx.adapters.containers) cx.win.open(cx.adapters.containers.host, value);
  };
  window.addEventListener("tracer:canvas-action", onAction, { signal });
  return removeProvider;
}
