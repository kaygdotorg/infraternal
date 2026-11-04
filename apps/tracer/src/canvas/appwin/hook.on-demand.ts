/**
 * App-window canvas lifecycle, loaded only when the feature is wanted and supported. Keeping its module graph behind
 * this boundary leaves the deferred canvas with a small availability loader.
 */
import { whenIdle } from "../../on-demand";
import type { PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, WinRec } from "../context";
import type { SessionBinding } from "../sessions/adapter";
import type { AppWindowsAdapter } from "./adapter";
import { createAppWindowsPart, type AppWindowsPart } from "./appwin.on-demand";

/** What the canvas calls on the app-window feature. Every method is safe to call while the feature is off: it then does nothing or returns an empty list. */
export interface AppWindowsHook {
  togglePicker(anchor: HTMLElement, source: PopoverSource, query?: string): void;
  paletteEntries(): PaletteEntry[];
  openFromPalette(value: string): void;
  bindingFor(rec: WinRec): SessionBinding | undefined;
  dispose(): void;
}

/** Installs the feature lifecycle after the canvas loader reaches this on-demand module. */
export function installAppWindowsRuntime(cx: Ctx, adapter: AppWindowsAdapter): AppWindowsHook {
  let part: AppWindowsPart | undefined;
  let disposed = false;
  const ensurePart = (): AppWindowsPart | undefined => {
    if (disposed || cx.signal.aborted || !adapter.available()) return undefined;
    return (part ??= createAppWindowsPart(cx, adapter));
  };
  const warm = (): void => {
    if (adapter.available()) whenIdle(() => { if (adapter.available()) ensurePart(); });
  };
  const off = adapter.onChange(() => {
    if (disposed || cx.signal.aborted) return;
    if (adapter.available()) warm();
    else {
      part?.dispose();
      part = undefined;
      // Dispose through the existing window lifecycle while the socket can still deliver Stop. Immediate removal also
      // prevents a rapid re-enable from finding a closing, already-disposed window as the existing target.
      const windows = [...cx.views.values()].flatMap(view => [...view.wins.values()]);
      for (const rec of windows) if (rec.model.kind === "app" || rec.model.kind === "screen") cx.win.close(rec, true);
    }
    cx.core.refreshPalette();
  });
  const removeProvider = cx.core.addPaletteProvider(() => (adapter.available() ? part?.paletteEntries() ?? [] : []));
  if (adapter.available()) ensurePart();
  cx.core.refreshPalette();
  return {
    togglePicker(anchor, source, query) { ensurePart()?.togglePicker(anchor, source, query); },
    paletteEntries: () => (adapter.available() ? part?.paletteEntries() ?? [] : []),
    openFromPalette(value) { ensurePart()?.openFromPalette(value); },
    bindingFor: (rec: WinRec): SessionBinding | undefined => part?.bindingFor(rec),
    dispose() {
      disposed = true;
      off();
      removeProvider();
      part?.dispose();
      part = undefined;
    },
  };
}
