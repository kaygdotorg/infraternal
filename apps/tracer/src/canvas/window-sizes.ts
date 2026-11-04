/**
 * Window sizes (D191, Settings -> Window Sizes): how wide a terminal window is by default, per kind of device.
 *
 * - Phones: "Edge to edge" (the default: a lone window is the screen width; in a strip it is narrower by the gap between
 *   columns and a slice of the neighbour on each side, so a thin slice of each neighbour shows), "Full width"
 *   (exactly the screen width between the safe areas; no neighbour shows) or "Comfortable" (the earlier phone width: the
 *   screen less the canvas margins).
 * - Desktop: "Comfortable" (one third of the canvas, the earlier width, the default), "Wide" (half) or "Full width"
 *   (99% of the canvas).
 *
 * The choice is a device-local preference like the theme and the font, and applies live. A window the person resized by
 * hand keeps its own width; only windows still at the default follow the setting.
 *
 * The UI size (#283) is a factor on every desktop default: a window is as many times wider as the UI is bigger, so the type
 * inside it has the room it had (owner, 2026-11-01: windows grow with the UI size). The ceiling below (99% of the canvas)
 * stays the ceiling at every size.
 */
import { readLocal, writeLocal } from "../../../../packages/ui/src/local-pref";

/** The phone choices: `full` = exactly the screen width, `edge` = edge to edge with a slice of each neighbour showing, `comfortable` = the screen less the canvas margins. */
export type PhoneSize = "full" | "edge" | "comfortable";
/** The desktop choices: one third of the canvas (`comfortable`), half (`wide`) or 99% (`full`). */
export type DesktopSize = "comfortable" | "wide" | "full";
/** The person's window-size choices, one for each kind of device. */
export interface WindowSizes { phone: PhoneSize; desktop: DesktopSize }

/** The choices when the person has made none. */
export const DEFAULT_SIZES: WindowSizes = { phone: "edge", desktop: "comfortable" };
/** The gap between two columns (px). A neighbour's slice starts this far past the window's edge. */
export const COLUMN_GAP = 12;
/** Dispatched on `window` by `writeSize`, so the canvas can re-measure at once. */
export const SIZE_EVENT = "tracer:window-size";

/** The local-storage keys of the two choices. */
const KEYS = { phone: "tracer.window-size.phone", desktop: "tracer.window-size.desktop" } as const;
/** The values a stored phone choice may have; anything else is ignored. */
const PHONE: readonly string[] = ["full", "edge", "comfortable"];
/** The values a stored desktop choice may have; anything else is ignored. */
const DESKTOP: readonly string[] = ["comfortable", "wide", "full"];

/** The person's choices from this browser. A missing or unrecognised stored value gives the default for that device. */
export function readSizes(): WindowSizes {
  const phone = readLocal(KEYS.phone), desktop = readLocal(KEYS.desktop);
  return {
    phone: phone && PHONE.includes(phone) ? (phone as PhoneSize) : DEFAULT_SIZES.phone,
    desktop: desktop && DESKTOP.includes(desktop) ? (desktop as DesktopSize) : DEFAULT_SIZES.desktop,
  };
}

/** Saves one choice on this browser and fires `SIZE_EVENT`. */
export function writeSize<K extends keyof WindowSizes>(kind: K, value: WindowSizes[K]): void {
  writeLocal(KEYS[kind], value);
  window.dispatchEvent(new CustomEvent(SIZE_EVENT));
}

/**
 * The widest a desktop column is drawn: the "Full width" size, 99% of the canvas area. A hand resize already stops here,
 * but the saved width is a weight times the default width, so a later change (a wider "Window Sizes" option, a narrower
 * window) made a saved column wider than the screen, and the canvas viewport clips what overhangs it.
 */
export const maxColumnWidth = (width: number): number => Math.max(480, Math.round(width * 0.99));

/**
 * The default column (window) width for a canvas area `width` px wide: the canvas viewport's client width, which is the
 * space between the screen margins on a phone set to "Comfortable" and the screen between the safe areas otherwise (see
 * `edgeToEdge`). `scale` is the UI size's factor (1 at the standard size; the base and the slider together). Pure, so it can be
 * tested alone.
 *
 * On a desktop the width of the chosen option is multiplied by `scale` and still never passes the ceiling. A phone's window is
 * the screen's width, so it has no factor: its type grows inside the same window.
 */
export function columnWidth(width: number, narrow: boolean, sizes: WindowSizes, scale = 1): number {
  if (narrow) {
    if (sizes.phone === "comfortable") return Math.max(260, Math.min(520, Math.round(width - 28)));
    // A lone window is the whole area between the safe areas in both settings (TASTE: a lone window keeps the full
    // phone width). In a strip, edge to edge narrows it by `peekWidth`, so it is never wider than full width.
    return Math.round(width);
  }
  if (sizes.desktop === "full") return maxColumnWidth(width);
  const option = sizes.desktop === "wide" ? Math.max(480, Math.min(960, Math.round((width - 24) / 2))) : Math.max(400, Math.min(640, Math.round((width - 24) / 3)));
  return Math.min(maxColumnWidth(width), Math.round(option * scale));
}

/**
 * Whether the canvas area spans the screen between the safe areas: a phone set to "Full width" or "Edge to edge". Both
 * compute their window from the same area, so the two settings can be compared directly. "Comfortable" keeps the top
 * bar's gutters.
 */
export const edgeToEdge = (narrow: boolean, sizes: WindowSizes): boolean => narrow && sizes.phone !== "comfortable";

/**
 * How much of a neighbouring window shows at the screen edge on a phone (px). Ten pixels is enough to see that there is
 * more to swipe to (a rounded corner and the hairline read clearly) and little enough that the window keeps its width:
 * eight looked like a rendering fault, twelve cost a character column on a 375 px phone.
 */
export const PEEK = 10;

/**
 * The width of a column in a strip of several, on a phone (except at full width): the screen less, on each side, the gap between columns and a
 * slice of the neighbour (`PEEK`). It never exceeds the lone-window width. Desktop strips need none (columns already fit
 * with neighbours beside them), so they keep `columnWidth`.
 */
export function peekWidth(width: number, narrow: boolean, alone: number, gap: number, sizes: WindowSizes = DEFAULT_SIZES): number {
  // Full width never peeks: its window is the same with neighbours as alone.
  return narrow && sizes.phone !== "full" ? Math.min(alone, Math.round(width - 2 * (gap + PEEK))) : alone;
}
