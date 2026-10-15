/**
 * The canvas side of app windows (D207, D208): the few lines that live on the canvas's own path. Everything heavy is
 * in `appwin.on-demand.ts` and loads only when the feature is available (wanted here, supported by the server), so a
 * canvas without the feature pays for this file and nothing else (D188).
 *
 * `installAppWindows` is called once by the composition root. With no adapter (mockups, an old server's canvas) it
 * returns nothing and the canvas never offers an app window: no picker row, no palette row, no switch.
 *
 * The hook answers four questions for the rest of the canvas without loading anything:
 * - `active`: is the feature on right now (the "+" opens a picker instead of a shell only then);
 * - `togglePicker`: open or close the picker (loading the code first, once);
 * - `paletteEntries` / `openFromPalette`: the "Open <app> on <machine>" rows, from the machines' cached answers;
 * - `bindingFor`: the body of an app or screen window, once the code is there (a window can only be opened by it).
 */
import { onDemand, whenIdle } from "../../on-demand";
import type { PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, WinRec } from "../context";
import type { SessionBinding } from "../sessions/adapter";
import type { AppWindowsPart } from "./appwin.on-demand";

export interface AppWindowsHook {
  /** The feature is available now. */
  readonly active: boolean;
  /** The server says it can stream (whether or not this browser wants it): Settings shows its switch on this. */
  readonly serverCan: boolean;
  /** The Settings switch (see `AppWindowsAdapter.setWanted`). */
  readonly pref: boolean;
  setWanted(on: boolean): void;
  /** Runs when the feature's availability may have changed (the switch, the server's Hello); returns the remover. */
  onChange(listener: () => void): () => void;
  /** `query` narrows the list when it opens (a machine's own pill opens it on that machine). */
  togglePicker(anchor: HTMLElement, source: PopoverSource, query?: string): void;
  paletteEntries(): PaletteEntry[];
  openFromPalette(value: string): void;
  /** The body of an app or screen window; undefined when the code is not loaded (the window then explains itself). */
  bindingFor(rec: WinRec): SessionBinding | undefined;
  /** Opens the picker's code ahead of need (the palette and the "+" use it). */
  warm(): void;
  dispose(): void;
}

export function installAppWindows(cx: Ctx): AppWindowsHook | undefined {
  const adapter = cx.adapters.appWindows;
  if (!adapter) return undefined;
  let part: AppWindowsPart | undefined;
  let loading: Promise<AppWindowsPart | undefined> | undefined;
  let generation = 0;
  let disposed = false;
  const load = (): Promise<AppWindowsPart | undefined> => {
    if (disposed || cx.signal.aborted || !adapter.available()) return Promise.resolve(undefined);
    if (!loading) {
      const epoch = generation;
      loading = onDemand(() => import("./appwin.on-demand")).then((m) => {
        // A queued import must not restart inventory work after preference-off,
        // capability withdrawal, or a newer enable generation.
        if (epoch !== generation || disposed || cx.signal.aborted || !adapter.available()) return undefined;
        return (part = m.createAppWindowsPart(cx, adapter));
      }).catch(() => {
        if (epoch === generation && !disposed && adapter.available()) {
          loading = undefined;
          cx.toast.show({ message: "Could not load app windows. Try again.", tone: "error", duration: 5000 });
        }
        return undefined;
      });
    }
    return loading;
  };
  const warm = (): void => { if (adapter.available()) whenIdle(() => { void load(); }); };
  warm();
  const off = adapter.onChange(() => {
    if (disposed || cx.signal.aborted) return;
    if (adapter.available()) warm();
    else {
      generation++;
      loading = undefined;
      part?.dispose();
      part = undefined;
      // Dispose through the existing window lifecycle while the socket can still
      // deliver Stop. Immediate removal also prevents a rapid re-enable from
      // finding a closing, already-disposed window as the existing target.
      const windows = [...cx.views.values()].flatMap(view => [...view.wins.values()]);
      for (const rec of windows) if (rec.model.kind === "app" || rec.model.kind === "screen") cx.win.close(rec, true);
    }
    cx.core.refreshPalette();
  });
  const removeProvider = cx.core.addPaletteProvider(() => (adapter.available() ? part?.paletteEntries() ?? [] : []));
  return {
    get active() { return adapter.available(); },
    get serverCan() { return adapter.serverCan(); },
    get pref() { return adapter.pref; },
    setWanted: (on) => adapter.setWanted(on),
    onChange: (listener) => adapter.onChange(listener),
    togglePicker(anchor, source, query) {
      if (!adapter.available()) return;
      if (part) { part.togglePicker(anchor, source, query); return; }
      void load().then((p) => { if (p && p === part && adapter.available() && anchor.isConnected) p.togglePicker(anchor, source, query); });
    },
    paletteEntries: () => (adapter.available() ? part?.paletteEntries() ?? [] : []),
    openFromPalette(value) { void load().then((p) => { if (p && p === part && adapter.available()) p.openFromPalette(value); }); },
    bindingFor: (rec) => part?.bindingFor(rec),
    warm,
    dispose() { disposed = true; generation++; off(); removeProvider(); part?.dispose(); part = undefined; loading = undefined; },
  };
}
