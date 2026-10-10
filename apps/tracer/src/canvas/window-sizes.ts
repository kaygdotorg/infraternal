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
 * The default column (window) width for a canvas area `width` px wide. `width` is the canvas viewport's client width,
 * which includes its own gutter padding on both sides; `gutter` is that padding. A phone's "full" and "edge" widths
 * are 99% of the space between the margins, so "full" keeps the gutter and "edge" (whose panes run to the screen
 * edges, see `edgeToEdge`) fills the screen. Pure, so it can be tested alone.
 */
export function columnWidth(width: number, narrow: boolean, sizes: WindowSizes, gutter = 0): number {
  if (narrow) return sizes.phone === "comfortable" ? Math.max(260, Math.min(520, Math.round(width - 28))) : Math.round((width - 2 * gutter) * 0.99);
  if (sizes.desktop === "full") return Math.max(480, Math.round(width * 0.99));
  if (sizes.desktop === "wide") return Math.max(480, Math.min(960, Math.round((width - 24) / 2)));
  return Math.max(400, Math.min(640, Math.round((width - 24) / 3)));
}

/**
 * Whether the canvas area runs edge to edge: only a phone whose person chose "Edge to edge". Every other phone size keeps
 * the top bar's gutter, so a resting window never touches the screen edge (TASTE: windows keep the gutter on phones).
 */
export const edgeToEdge = (narrow: boolean, sizes: WindowSizes): boolean => narrow && sizes.phone === "edge";
