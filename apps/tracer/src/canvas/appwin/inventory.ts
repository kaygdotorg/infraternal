/**
 * What a machine can stream: its open app windows and its screens, as the `desktop.windows` action reports them
 * (contracts/desktop-helper.md, "Window inventory JSON"), reduced to what the picker and the palette show.
 *
 * The parser is defensive on purpose: the reply comes from another machine through the server, so every field is
 * checked and bounded, a malformed row is dropped (never the whole list), and a missing optional field means "not
 * said". Window identity is `(owner_pid, window_id)` and only lives as long as the window does, which is why an app
 * window on the canvas is never saved with the layout (a restored window id could name a different window).
 *
 * Pure functions, no DOM: unit-tested in `inventory.test.ts`.
 */

/** What a stream shows: one window of one app, or one whole display. */
export type AppTarget =
  | { type: "window"; windowId: number; ownerPid: number }
  | { type: "screen"; displayId: number };

/** One streamable app window, with the identity the stream needs (`target`) and the words the picker shows. */
export interface AppWindowEntry {
  kind: "window";
  /** Stable for the life of the window: `w-<pid>-<id>`. No colon: it travels inside a palette action, which splits on colons. */
  key: string;
  target: Extract<AppTarget, { type: "window" }>;
  appName: string;
  title: string;
  bundleId?: string;
  /** False for a window that is minimised or hidden on the machine. */
  onScreen: boolean;
  /** Point size on the machine, when it said. */
  size?: { width: number; height: number };
}

/** One streamable display. */
export interface ScreenEntry {
  kind: "screen";
  key: string;
  target: Extract<AppTarget, { type: "screen" }>;
  /** "Whole screen" for the only display, "Display 2" and so on otherwise. */
  name: string;
  pixels?: { width: number; height: number };
  /** The machine's pixel density (2 on a Retina screen). */
  backingScale: number;
}

/** Anything the picker can offer to stream. */
export type Entry = AppWindowEntry | ScreenEntry;

/** The two permissions macOS asks the person at the machine for (D208). `undefined` means the machine did not say. */
export interface Permissions { screenRecording?: boolean; accessibility?: boolean }

/** A machine's streamable windows and screens, plus the permissions it reported. */
export interface Inventory {
  windows: AppWindowEntry[];
  screens: ScreenEntry[];
  permissions: Permissions;
}

/** Windows beyond this many in one reply are ignored. */
const MAX_ROWS = 2000;
/** Longest accepted text field; a longer one counts as not said. */
const MAX_TEXT = 512;
/** A string no longer than `max`, else `undefined`. */
const text = (value: unknown, max = MAX_TEXT): string | undefined => (typeof value === "string" && value.length <= max ? value : undefined);
/** An integer within `min`–`max`, else `undefined`. */
const int = (value: unknown, min: number, max: number): number | undefined => (typeof value === "number" && Number.isInteger(value) && value >= min && value <= max ? value : undefined);
/** A finite number within `min`–`max`, else `undefined`. */
const finite = (value: unknown, min: number, max: number): number | undefined => (typeof value === "number" && Number.isFinite(value) && value >= min && value <= max ? value : undefined);

/** A frame is `[x, y, width, height]` or `{ x, y, width, height }`; only the size is used. */
function frameSize(value: unknown): { width: number; height: number } | undefined {
  let width: number | undefined, height: number | undefined;
  if (Array.isArray(value) && value.length === 4) { width = finite(value[2], 0, 1e6); height = finite(value[3], 0, 1e6); }
  else if (value && typeof value === "object") {
    const f = value as Record<string, unknown>;
    width = finite(f.width ?? f.w, 0, 1e6); height = finite(f.height ?? f.h, 0, 1e6);
  }
  return width === undefined || height === undefined ? undefined : { width, height };
}

/** Windows under this many points on a side are toolbars, shadows and badges, not something to stream. */
const MIN_SIDE = 60;

/**
 * Shapes the machine's reply into an `Inventory`. Never throws: anything that is not an object gives an empty inventory. A window row is
 * dropped when its ids are missing or out of range, when it is not on layer 0, when it is under 60 points on a side, when it has no app
 * name, or when it repeats an earlier key. Up to 16 displays are kept. Windows are sorted on-screen first, then by app, title and id.
 */
export function parseInventory(value: unknown): Inventory {
  const root = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const windows: AppWindowEntry[] = [];
  const seen = new Set<string>();
  if (Array.isArray(root.windows)) {
    for (const row of root.windows.slice(0, MAX_ROWS)) {
      if (!row || typeof row !== "object") continue;
      const r = row as Record<string, unknown>;
      const windowId = int(r.window_id, 1, 0xffff_ffff), ownerPid = int(r.owner_pid, 1, 0x7fff_ffff);
      if (windowId === undefined || ownerPid === undefined) continue;
      // Layer 0 is a normal window; the menu bar, the dock and overlays sit on other layers and are never offered.
      if (r.layer !== undefined && r.layer !== 0) continue;
      const size = frameSize(r.frame);
      if (size && (size.width < MIN_SIDE || size.height < MIN_SIDE)) continue;
      const appName = text(r.app_name)?.trim();
      if (!appName) continue;
      const key = `w-${ownerPid}-${windowId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const bundleId = text(r.bundle_id, 256);
      windows.push({
        kind: "window", key, target: { type: "window", windowId, ownerPid }, appName, title: text(r.title)?.trim() ?? "",
        ...(bundleId ? { bundleId } : {}), onScreen: r.on_screen !== false, ...(size ? { size } : {}),
      });
    }
  }
  // On-screen windows first, then by app and title: a stable order, so the list never shuffles under the pointer.
  windows.sort((a, b) => Number(b.onScreen) - Number(a.onScreen) || a.appName.localeCompare(b.appName) || a.title.localeCompare(b.title) || a.target.windowId - b.target.windowId);
  const screens: ScreenEntry[] = [];
  if (Array.isArray(root.displays)) {
    for (const row of root.displays.slice(0, 16)) {
      if (!row || typeof row !== "object") continue;
      const r = row as Record<string, unknown>;
      const displayId = int(r.display_id, 1, 0xffff_ffff);
      if (displayId === undefined) continue;
      const w = int(r.pixel_width, 1, 65536), h = int(r.pixel_height, 1, 65536);
      screens.push({ kind: "screen", key: `s-${displayId}`, target: { type: "screen", displayId }, name: "", ...(w && h ? { pixels: { width: w, height: h } } : {}), backingScale: finite(r.backing_scale, 1, 4) ?? 2 });
    }
  }
  screens.forEach((s, i) => { s.name = screens.length === 1 ? "Whole screen" : `Display ${i + 1}`; });
  const p = root.permission_state && typeof root.permission_state === "object" ? root.permission_state as Record<string, unknown> : {};
  const permissions: Permissions = {
    ...(typeof p.screen_recording === "boolean" ? { screenRecording: p.screen_recording } : {}),
    ...(typeof p.accessibility === "boolean" ? { accessibility: p.accessibility } : {}),
  };
  return { windows, screens, permissions };
}

/** The line a row shows under the app name: the window's title, or what the window is when it has none. */
export function entryTitle(entry: Entry): string {
  if (entry.kind === "screen") return entry.pixels ? `${entry.pixels.width} × ${entry.pixels.height}` : "Everything on this machine's display";
  return entry.title || (entry.onScreen ? "Untitled window" : "Minimised");
}

/** The words the search field matches a row against: app, title, bundle and the words a person would say. */
export function searchText(entry: Entry): string {
  if (entry.kind === "screen") return `${entry.name} screen display desktop`.toLowerCase();
  return `${entry.appName} ${entry.title} ${entry.bundleId ?? ""}`.toLowerCase();
}

/** Every word of the query must appear (in any order), so "code readme" finds the Code window titled README. */
export function matches(entry: Entry, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = searchText(entry);
  return words.every((w) => hay.includes(w));
}

/** Whether two inventories list the same rows with the same words (a poll that changed nothing repaints nothing). */
export function sameInventory(a: Inventory, b: Inventory): boolean {
  if (a.windows.length !== b.windows.length || a.screens.length !== b.screens.length) return false;
  if (a.permissions.screenRecording !== b.permissions.screenRecording || a.permissions.accessibility !== b.permissions.accessibility) return false;
  return a.windows.every((w, i) => { const o = b.windows[i]!; return w.key === o.key && w.title === o.title && w.appName === o.appName && w.onScreen === o.onScreen; })
    && a.screens.every((s, i) => { const o = b.screens[i]!; return s.key === o.key && s.name === o.name; });
}

/** The tile letter for an app that has no icon of its own on the wire: its first letter or digit. */
export function appInitial(appName: string): string {
  const match = appName.match(/[\p{L}\p{N}]/u);
  return (match?.[0] ?? "?").toUpperCase();
}
