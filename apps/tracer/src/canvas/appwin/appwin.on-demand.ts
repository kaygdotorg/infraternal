/**
 * App windows and screens on the canvas (D200, D207, D208): the on-demand half. It loads the first time the feature is
 * available (`hook.ts`), never for a person who has not turned it on.
 *
 * It owns the machines' cached window lists, the "New window" picker, the palette rows ("Open <app> on <machine>"),
 * and the making of an app or screen window: a window model for the machine's stream, opened as one more column in
 * Console, whose body is an `AppBinding`. An app window is never saved with the layout: the machine's window identity
 * only lives as long as the window does, and a restored id could name another window.
 *
 * Opening what is already open takes you to it: one window per stream target on a machine.
 */
import type { PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, WinRec } from "../context";
import type { SessionBinding } from "../sessions/adapter";
import type { HostEntry } from "../sessions/adapter";
import type { ViewId, WindowModel } from "../model/types";
import type { AppWindowsAdapter } from "./adapter";
import type { AppTarget, Entry } from "./inventory";
import { Machines, STALE_MS } from "./machines";
import { Picker, paletteRows, type Choice } from "./picker";
import { AppBinding } from "./window-body";

declare const __CLUSTERS_PREVIEW__: boolean;

/** The styles of this feature load with it, not with the page. */
function loadStyles(): void {
  if (document.querySelector('link[data-appwin-css]')) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = new URL("appwin.css", document.baseURI).href;
  link.dataset.appwinCss = "";
  document.head.append(link);
}

export interface AppWindowsPart {
  togglePicker(anchor: HTMLElement, source: PopoverSource, query?: string): void;
  paletteEntries(): PaletteEntry[];
  openFromPalette(value: string): void;
  bindingFor(rec: WinRec): SessionBinding | undefined;
  /** The machines' cached answers (tests and measurement). */
  readonly machines: Machines;
  /** Every app window's state and its decode worker's counters (measurement). */
  report(): Promise<Array<{ id: string; state: string; control: string; stats: unknown }>>;
  /** The source target stored on each canvas model (measurement). */
  targets(): Array<{ id: string; target: AppTarget }>;
  dispose(): void;
}

const SCREEN_ICON = '<rect x="3" y="4.5" width="18" height="12.5" rx="2.5"/><path d="M8.5 20.5h7M12 17v3.5"/>';
const WINDOW_ICON = '<rect x="3.5" y="5" width="17" height="14" rx="2.5"/><path d="M3.5 9.5h17"/>';

/**
 * The words in a window's pill: "title · App", or the display's name. The title comes first because it is the part that
 * tells two windows of one app apart, and a narrow pill is cut from the end: the part that differs is the part that
 * survives. An untitled window is just the app's name.
 */
export function streamLabel(entry: Entry): string {
  if (entry.kind === "screen") return entry.name;
  return entry.title ? `${entry.title} · ${entry.appName}` : entry.appName;
}

export function createAppWindowsPart(cx: Ctx, adapter: AppWindowsAdapter): AppWindowsPart {
  loadStyles();
  const machines = new Machines(adapter.connection, () => cx.adapters.sessions.hosts());
  let picker: Picker | undefined;
  let paletteWatch = 0;

  /** The palette asked: rows come from the cached answers now, and a stale copy is asked again; the palette refreshes when it lands. */
  const offChange = machines.onChange(() => { if (performance.now() - paletteWatch < 10_000) cx.core.refreshPalette(); });
  // The first palette opens with the lists already there: they are asked once the code is loaded (one small call per Mac), and
  // again when the set of hosts changes (a Mac appears or goes), so the palette never starts cold.
  machines.refreshAll();
  const offHosts = cx.adapters.sessions.onChange(() => machines.refreshAll(STALE_MS));

  const existing = (machine: HostEntry, entry: Entry): WinRec | undefined => {
    for (const c of cx.views.values()) for (const rec of c.wins.values()) {
      const s = rec.model.stream;
      if (rec.closing || !s || rec.model.hostId !== machine.id) continue;
      if (s.target.type === entry.target.type && JSON.stringify(s.target) === JSON.stringify(entry.target)) return rec;
    }
    return undefined;
  };

  /** The shape the machine listed for a window (points) or a screen (pixels), if it said. */
  const listedAspect = (entry: Entry): number | undefined => {
    const size = entry.kind === "window" ? entry.size : entry.pixels;
    return size && size.width > 0 && size.height > 0 ? size.width / size.height : undefined;
  };

  /** App-window-only window creation stays with the feature instead of enlarging the shared window lifecycle. */
  const openModel = (model: WindowModel): void => {
    const c = cx.views.get("console" as ViewId);
    if (!c) return;
    const here = cx.state.currentView === "console" || cx.camera.band === "out";
    const rec = cx.win.addColumn(c, model, c.view.cols.length, cx.state.metrics.colW, !here, true);
    cx.win.setActive(rec);
    cx.nav.focusWindow(rec);
  };

  const open = (machine: HostEntry, entry: Entry): void => {
    const there = existing(machine, entry);
    if (there) { cx.win.setActive(there); cx.nav.focusWindow(there); cx.win.pulse(there); return; }
    const aspect = listedAspect(entry);
    const model: WindowModel = {
      id: `a-${crypto.randomUUID()}`, kind: entry.kind === "screen" ? "screen" : "app", host: machine.name, hostId: machine.id,
      ...(machine.user ? { user: machine.user } : {}), ...(machine.os ? { os: machine.os } : {}),
      session: streamLabel(entry),
      stream: { target: entry.target, appName: entry.kind === "screen" ? entry.name : entry.appName, title: entry.kind === "screen" ? "" : entry.title, ...(entry.kind === "window" && entry.bundleId ? { bundleId: entry.bundleId } : {}), ...(aspect !== undefined ? { aspect } : {}) },
    };
    openModel(model);
  };

  const choose = (choice: Choice, how: PopoverSource): void => {
    picker?.close(how);
    if (choice.kind === "shell") cx.win.open(choice.machine.id);
    else open(choice.machine, choice.entry);
  };

  const part: AppWindowsPart = {
    machines,
    togglePicker(anchor, source, query) {
      if (picker) { picker.close(source); return; }
      picker = new Picker(cx, machines, anchor, source, choose, () => { picker = undefined; }, query);
    },
    paletteEntries() {
      paletteWatch = performance.now();
      machines.refreshAll(STALE_MS);
      return paletteRows(machines).map(({ machine, entry, label, hint }): PaletteEntry => ({
        group: "Windows", glyph: "▢", icon: entry.kind === "screen" ? SCREEN_ICON : WINDOW_ICON,
        label, hint, action: `canvas:appwin:${machine.id}/${entry.key}`,
      }));
    },
    openFromPalette(value) {
      const at = value.indexOf("/");
      const machine = cx.adapters.sessions.hosts().find((h) => h.id === value.slice(0, at));
      const inv = machine && machines.state(machine.id)?.inventory;
      const key = value.slice(at + 1);
      const entry = inv && [...inv.screens, ...inv.windows].find((e) => e.key === key);
      if (machine && entry) open(machine, entry);
      else cx.toast.show({ message: "That window is gone. Search again.", tone: "error", duration: 4000 });
    },
    bindingFor(rec) {
      const m = rec.model;
      if (!m.stream || !m.hostId) return undefined;
      return new AppBinding(cx, rec, { connection: adapter.connection, hostId: m.hostId, target: m.stream.target, machine: m.host, app: m.stream.appName, ...(m.stream.aspect ? { aspect: m.stream.aspect } : {}) });
    },
    async report() {
      const out: Array<{ id: string; state: string; control: string; stats: unknown }> = [];
      for (const c of cx.views.values()) for (const rec of c.wins.values()) {
        const b = rec.binding;
        if (b instanceof AppBinding) out.push({ id: rec.model.id, state: b.streamState.kind, control: b.streamControl.kind, stats: await b.stats() });
      }
      return out;
    },
    targets() {
      const out: Array<{ id: string; target: AppTarget }> = [];
      for (const c of cx.views.values()) for (const rec of c.wins.values()) {
        const target = rec.model.stream?.target;
        if (target) out.push({ id: rec.model.id, target });
      }
      return out;
    },
    dispose() { offChange(); offHosts(); picker?.close("keyboard"); machines.dispose(); },
  };
  // Preview builds expose the counters to the browser checks and the frame-time measurements; production builds do not.
  if (typeof __CLUSTERS_PREVIEW__ !== "undefined" && __CLUSTERS_PREVIEW__) Object.assign(window, { __appwin: part, __appwinCx: cx });
  return part;
}
