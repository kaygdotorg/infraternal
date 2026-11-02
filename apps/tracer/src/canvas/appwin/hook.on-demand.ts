/**
 * App-window canvas lifecycle, loaded with its picker and stream body. Keeping the large feature module graph behind
 * this boundary leaves only the availability bridge in the shared canvas bundle.
 */
import { whenIdle } from "../../on-demand";
import type { Ctx, WinRec } from "../context";
import type { SessionBinding } from "../sessions/adapter";
import type { AppWindowsAdapter } from "./adapter";
import { createAppWindowsPart, type AppWindowsPart } from "./appwin.on-demand";
import type { AppWindowsHook } from "./hook";

/** Installs the feature lifecycle after the shared bridge has loaded this on-demand module. */
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
    get active() { return adapter.available(); },
    get serverCan() { return adapter.serverCan(); },
    get pref() { return adapter.pref; },
    setWanted: (on) => adapter.setWanted(on),
    onChange: (listener) => adapter.onChange(listener),
    togglePicker(anchor, source, query) { ensurePart()?.togglePicker(anchor, source, query); },
    paletteEntries: () => (adapter.available() ? part?.paletteEntries() ?? [] : []),
    openFromPalette(value) { ensurePart()?.openFromPalette(value); },
    bindingFor: (rec: WinRec): SessionBinding | undefined => part?.bindingFor(rec),
    warm,
    dispose() {
      disposed = true;
      off();
      removeProvider();
      part?.dispose();
      part = undefined;
    },
  };
}
