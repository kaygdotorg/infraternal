/**
 * The machine's pointer, drawn by the page (#146).
 *
 * The picture of a window or screen no longer contains the machine's pointer: a pointer inside video arrives a whole
 * capture-and-network pipeline after the person moved it, so it trailed the page's own pointer and two showed. Now the
 * page's own pointer is the only one, and it takes the machine's shape: the machine reports the image it is showing,
 * its hotspot and its pixel density on every status reply (`Cursor.swift`), named by a short id. The page makes one CSS
 * cursor per id and keeps it, so a shape that comes back (arrow, text bar, arrow) costs nothing.
 *
 * Nothing here touches the DOM; `window-body.ts` applies the CSS value to the stage.
 */

/** One pointer shape as the machine reports it, checked and ready to turn into CSS. */
export interface PointerShape {
  /** The machine's name for this image (16 lowercase hex characters); equal ids mean equal pictures. */
  id: string;
  /** The PNG, base64 encoded, exactly as sent. */
  png: string;
  /** The hotspot in points from the image's top left: the pixel that is "where the pointer is". */
  hotX: number;
  hotY: number;
  /** Pixels per point of the image: 2 for a Retina pointer. */
  scale: number;
  /** The image's size in pixels. */
  width: number;
  height: number;
}

/** Browsers ignore cursor images above this many pixels on a side (Chromium and Firefox both cap at 128). */
const MAX_PIXELS = 128;
/** A PNG this small covers every system pointer many times over; a bigger one is refused, never decoded. */
const MAX_BASE64 = 24_000;
/** The shape the person sees until the machine has reported one, and whenever a reported shape is unusable. */
export const DEFAULT_POINTER = "default";

/** True for a finite number from `min` to `max` inclusive. */
const within = (n: unknown, min: number, max: number): n is number => typeof n === "number" && Number.isFinite(n) && n >= min && n <= max;

/**
 * Reads the `cursor` object of the machine's status reply. Returns `undefined` for anything that is not a complete,
 * in-range shape, so a malformed or oversized report can never reach a style attribute. The hotspot must lie inside the
 * image, the density between 1 and 4, and the image within the browsers' cursor limit.
 */
export function parsePointerShape(value: unknown): PointerShape | undefined {
  if (!value || typeof value !== "object") return undefined;
  const v = value as Record<string, unknown>;
  const { id, png, hot_x: hotX, hot_y: hotY, scale, width, height } = v;
  if (typeof id !== "string" || !/^[0-9a-f]{16}$/.test(id)) return undefined;
  if (typeof png !== "string" || png.length === 0 || png.length > MAX_BASE64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(png)) return undefined;
  if (!within(width, 1, MAX_PIXELS) || !within(height, 1, MAX_PIXELS) || !Number.isInteger(width) || !Number.isInteger(height)) return undefined;
  if (!within(scale, 1, 4)) return undefined;
  if (!within(hotX, 0, width / scale) || !within(hotY, 0, height / scale)) return undefined;
  return { id, png, hotX, hotY, scale, width, height };
}

/**
 * The CSS `cursor` value that draws `shape`: the image at its density, the hotspot, and the ordinary pointer as the
 * fallback for a browser that refuses the image. Hotspot numbers are rounded to whole CSS pixels, which is what
 * browsers accept.
 */
export function pointerCss(shape: PointerShape | undefined): string {
  if (!shape) return DEFAULT_POINTER;
  const url = `url("data:image/png;base64,${shape.png}")`;
  return `image-set(${url} ${shape.scale}x) ${Math.round(shape.hotX)} ${Math.round(shape.hotY)}, ${DEFAULT_POINTER}`;
}
