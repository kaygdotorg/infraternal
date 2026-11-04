/**
 * The switch for app windows and whole-screen windows (D200, D207, D208). Everything else of the feature loads on
 * demand (`appwin.on-demand.ts`); this file is the only part on the first-screen path, and it is a few lines.
 *
 * The feature is off by default. It is wanted when
 * - a preview build is opened with `?appwin=1` (the testing door; production builds ignore the parameter), or
 * - the person turned on "App windows" in Settings, Hosts. That row is shown only when the server says it can stream
 *   (the desktop video bit of its Hello), so a server without the feature never offers a switch that does nothing.
 *
 * Wanting is not enough: the feature is live only when the server also reports the capability, which `MuxConnection`
 * learns from its Hello. A client advertises the capability in its own Hello only while it is wanted, so a person who
 * never turns the feature on never opens a desktop stream.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";

declare const __CLUSTERS_PREVIEW__: boolean;

/** The local-storage key of the Settings switch. */
const PREF = "infraternal.app-windows";
/** Dispatched on `window` when the preference changes, so Settings and the canvas follow it live. */
export const APPWIN_EVENT = "infraternal:app-windows";

/** True for a preview build opened with `?appwin=1`. Production builds compile this to false. */
export function appwinPreviewFlag(): boolean {
  if (typeof __CLUSTERS_PREVIEW__ === "undefined" || !__CLUSTERS_PREVIEW__) return false;
  try { return new URLSearchParams(location.search).get("appwin") === "1"; } catch { return false; }
}

/** Whether this browser wants app windows (the preview door or the Settings switch). */
export function appWindowsWanted(): boolean { return appwinPreviewFlag() || readLocal(PREF) === "1"; }

/** The Settings switch alone, without the preview door. */
export function readAppWindowsPref(): boolean { return readLocal(PREF) === "1"; }

/** Remembers the Settings switch on this browser ("1" or "0") and fires `APPWIN_EVENT` so listeners can follow at once. */
export function writeAppWindowsPref(on: boolean): void {
  writeLocal(PREF, on ? "1" : "0");
  window.dispatchEvent(new Event(APPWIN_EVENT));
}
