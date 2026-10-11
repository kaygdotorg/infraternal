/**
 * Window sizes (D191, Settings -> Window Sizes): how wide a terminal window is by default, per kind of device.
 *
 * - Phones: "Full width" (the default: 99% of the space between the screen margins, so a window keeps the gutter), "Edge
 *   to edge" (99% of the screen; the window touches both edges, only when the person chose it) or "Comfortable" (the
 *   earlier phone width: the screen less the canvas margins).
 * - Desktop: "Comfortable" (one third of the canvas, the earlier width, the default), "Wide" (half) or "Full width"
 *   (99% of the canvas).
 *
 * The choice is a device-local preference like the theme and the font, and applies live. A window the person resized by
 * hand keeps its own width; only windows still at the default follow the setting.
 */
import { readLocal, writeLocal } from "../../../../packages/ui/src/local-pref";

export type PhoneSize = "full" | "edge" | "comfortable";
export type DesktopSize = "comfortable" | "wide" | "full";
export interface WindowSizes { phone: PhoneSize; desktop: DesktopSize }

export const DEFAULT_SIZES: WindowSizes = { phone: "full", desktop: "comfortable" };
export const SIZE_EVENT = "tracer:window-size";

const KEYS = { phone: "tracer.window-size.phone", desktop: "tracer.window-size.desktop" } as const;
const PHONE: readonly string[] = ["full", "edge", "comfortable"];
const DESKTOP: readonly string[] = ["comfortable", "wide", "full"];

export function readSizes(): WindowSizes {
  const phone = readLocal(KEYS.phone), desktop = readLocal(KEYS.desktop);
  return {
    phone: phone && PHONE.includes(phone) ? (phone as PhoneSize) : DEFAULT_SIZES.phone,
    desktop: desktop && DESKTOP.includes(desktop) ? (desktop as DesktopSize) : DEFAULT_SIZES.desktop,
  };
}

export function writeSize<K extends keyof WindowSizes>(kind: K, value: WindowSizes[K]): void {
  writeLocal(KEYS[kind], value);
  window.dispatchEvent(new CustomEvent(SIZE_EVENT));
}

/**
 * The default column (window) width for a canvas area `width` px wide: the canvas viewport's client width, which is the
 * space between the screen margins on a phone (the panes keep the gutter) and the whole screen when the phone is set to
 * "Edge to edge" (see `edgeToEdge`). Pure, so it can be tested alone.
 */
export function columnWidth(width: number, narrow: boolean, sizes: WindowSizes): number {
  if (narrow) return sizes.phone === "comfortable" ? Math.max(260, Math.min(520, Math.round(width - 28))) : Math.round(width * 0.99);
  if (sizes.desktop === "full") return Math.max(480, Math.round(width * 0.99));
  if (sizes.desktop === "wide") return Math.max(480, Math.min(960, Math.round((width - 24) / 2)));
  return Math.max(400, Math.min(640, Math.round((width - 24) / 3)));
}

/**
 * Whether the canvas area runs edge to edge: only a phone whose person chose "Edge to edge". Every other phone size keeps
 * the top bar's gutter, so a resting window never touches the screen edge (TASTE: windows keep the gutter on phones).
 */
export const edgeToEdge = (narrow: boolean, sizes: WindowSizes): boolean => narrow && sizes.phone === "edge";

/**
 * How much of a neighbouring window shows at the screen edge on a phone (px). Ten pixels is enough to see that there is
 * more to swipe to (a rounded corner and the hairline read clearly) and little enough that the window keeps its width:
 * eight looked like a rendering fault, twelve cost a character column on a 375 px phone.
 */
export const PEEK = 10;

/**
 * The width of a column in a strip of several, on a phone: the screen less, on each side, the gap between columns and a
 * slice of the neighbour (`PEEK`). It never exceeds the lone-window width. Desktop strips need none (columns already fit
 * with neighbours beside them), so they keep `columnWidth`.
 */
export function peekWidth(width: number, narrow: boolean, alone: number, gap: number): number {
  return narrow ? Math.min(alone, Math.round(width - 2 * (gap + PEEK))) : alone;
}
