/** Pure v1 layout schema and bounded decoder, independent of runtime geometry and rendering (D180, D245). */
import { isCanonicalUuid } from "../../identifiers";
export const FORMAT = "infraternal.canvas";
export const VERSION = 1;
/** Smallest canonical column share accepted by the server. */
export const MIN_COLUMN_WEIGHT = 0.1;
/** The smallest height ratio a window may carry on the wire (matches the server's sizing bound). */
export const MIN_WINDOW_HEIGHT = 0.05;

/** What a window shows, by stable reference. */
export type DocTarget =
  | { type: "session"; id: string; host: string; hostId?: string; user?: string; address?: string; name?: string; pinned?: boolean }
  | { type: "settings"; section: string }
  | { type: "containers" | "logs"; host: string };

export interface DocWindow {
  /** Stable id of the window (not of its session). */
  id: string;
  target: DocTarget;
  /** The window's height as a share of its column; absent when the column shares equally. */
  height?: number;
  /** Columns covered from its own column (D212); absent means one. Old documents never have it. */
  span?: number;
  /** Row bands covered (D212); absent means one. */
  rows?: number;
  /** The band it starts in, saved only for a window in a group (D212); a plain column stacks by list order. */
  row?: number;
}
export interface DocColumn { id: string; weight: number; windows: DocWindow[] }
export type DocLayout =
  | { type: "tiled"; columns: DocColumn[] }
  | { type: "graph"; pinned: Record<string, { x: number; y: number }> };
export interface DocView { id: string; kind: string; name: string; cell: { x: number; y: number }; layout: DocLayout }

/** One theme of the account's look, as it travels in the document (the model of `themes/model.ts` is exactly this shape). */
export interface DocTheme {
  id: string; name: string; tint: number; blur: number; grain: number; font: string; colors: string; uiSize: number; background: string; customSolid: string;
  custom: { stops: string[]; angle: number };
}
/**
 * The account's look (D322): its themes, which one is selected, and the Colour, font and size the built-in themes started from. It is part of the
 * canvas document so every device of the account shows the same look; only the camera stays per device (D178).
 */
export interface DocLook { v: 1; selected: string; basics: { colors: string; font: string; uiSize: number }; themes: DocTheme[] }

/** The most themes one account's look may hold: an intent carries the whole list and an intent is at most 8 KiB (the server's own bound). */
export const MAX_THEMES = 16;

export interface CanvasDocument {
  format: typeof FORMAT;
  version: typeof VERSION;
  revision: number;
  views: DocView[];
  /** The account's look; absent until a device has saved one (older documents never have it). */
  look?: DocLook;
}

/** Enumerate drawing memberships without consulting device-local terminal attachments. */
export function documentWindows(document: CanvasDocument): DocWindow[] {
  return document.views.flatMap((view) => view.layout.type === "tiled" ? view.layout.columns.flatMap((col) => col.windows) : []);
}

const MAX_VIEWS = 64, MAX_COLUMNS = 64, MAX_WINDOWS = 256, MAX_TEXT = 200, MAX_BANDS = 64;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;
const finite = (v: unknown, lo: number, hi: number): v is number => typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi;

function parseTarget(v: unknown): DocTarget | undefined {
  if (!isObject(v)) return undefined;
  if (v.type === "session" && text(v.id) && text(v.host) && (v.hostId === undefined || isCanonicalUuid(v.hostId)) && (v.pinned === undefined || typeof v.pinned === "boolean")) return { type: "session", id: v.id, host: v.host, ...(isCanonicalUuid(v.hostId) ? { hostId: v.hostId, ...(text(v.user) ? { user: v.user } : {}), ...(text(v.address) ? { address: v.address } : {}) } : {}), ...(text(v.name) ? { name: v.name } : {}), ...(v.pinned === true ? { pinned: true } : {}) };
  if (v.type === "settings" && text(v.section)) return { type: "settings", section: v.section };
  if ((v.type === "containers" || v.type === "logs") && text(v.host)) return { type: v.type, host: v.host };
  return undefined;
}

const whole = (v: unknown, lo: number, hi: number): v is number => finite(v, lo, hi) && Number.isInteger(v);
const hex = (v: unknown): v is string => typeof v === "string" && /^#[0-9a-fA-F]{6}$/.test(v);

/** Checks an untrusted look with the server's bounds (text up to 200 characters, percentages 0 to 100, size 50 to 150, hex colours, at most 16 distinct themes). */
export function parseLook(input: unknown): DocLook | undefined {
  if (!isObject(input) || input.v !== 1 || !text(input.selected) || !isObject(input.basics) || !Array.isArray(input.themes) || input.themes.length > MAX_THEMES) return undefined;
  const b = input.basics;
  if (!text(b.colors) || !text(b.font) || !whole(b.uiSize, 50, 150)) return undefined;
  const themes: DocTheme[] = [];
  for (const t of input.themes) {
    if (!isObject(t) || !text(t.id) || !text(t.name) || !text(t.font) || !text(t.colors) || !text(t.background) || !whole(t.tint, 0, 100) || !whole(t.blur, 0, 100) || !whole(t.grain, 0, 100) || !whole(t.uiSize, 50, 150) || !hex(t.customSolid) || !isObject(t.custom)) return undefined;
    const c = t.custom;
    if (!Array.isArray(c.stops) || c.stops.length < 2 || c.stops.length > 4 || !c.stops.every(hex) || !whole(c.angle, 0, 360) || themes.some((seen) => seen.id === t.id)) return undefined;
    themes.push({ id: t.id, name: t.name, tint: t.tint, blur: t.blur, grain: t.grain, font: t.font, colors: t.colors, uiSize: t.uiSize, background: t.background, customSolid: t.customSolid, custom: { stops: [...c.stops as string[]], angle: c.angle } });
  }
  return { v: 1, selected: input.selected, basics: { colors: b.colors, font: b.font, uiSize: b.uiSize }, themes };
}

/** Checks untrusted JSON and returns a document, or nothing. */
export function parseDocument(input: unknown): CanvasDocument | undefined {
  if (!isObject(input) || input.format !== FORMAT || input.version !== VERSION || !finite(input.revision, 0, Number.MAX_SAFE_INTEGER)) return undefined;
  if (!Array.isArray(input.views) || input.views.length > MAX_VIEWS) return undefined;
  const views: DocView[] = [];
  for (const raw of input.views) {
    if (!isObject(raw) || !text(raw.id) || !text(raw.kind) || !text(raw.name) || !isObject(raw.cell) || !finite(raw.cell.x, -1000, 1000) || !finite(raw.cell.y, -1000, 1000) || !isObject(raw.layout)) return undefined;
    const cell = { x: Math.round(raw.cell.x), y: Math.round(raw.cell.y) };
    if (raw.layout.type === "graph") {
      if (!isObject(raw.layout.pinned)) return undefined;
      const pinned: Record<string, { x: number; y: number }> = {};
      for (const [k, p] of Object.entries(raw.layout.pinned)) {
        if (!isObject(p) || !finite(p.x, -100000, 100000) || !finite(p.y, -100000, 100000)) return undefined;
        pinned[k] = { x: p.x, y: p.y };
      }
      views.push({ id: raw.id, kind: raw.kind, name: raw.name, cell, layout: { type: "graph", pinned } });
      continue;
    }
    if (raw.layout.type !== "tiled" || !Array.isArray(raw.layout.columns) || raw.layout.columns.length > MAX_COLUMNS) return undefined;
    const columns: DocColumn[] = [];
    let count = 0;
    for (const c of raw.layout.columns) {
      if (!isObject(c) || !text(c.id) || !finite(c.weight, MIN_COLUMN_WEIGHT, 10) || !Array.isArray(c.windows)) return undefined;
      const windows: DocWindow[] = [];
      for (const w of c.windows) {
        const target = isObject(w) ? parseTarget(w.target) : undefined;
        if (!isObject(w) || !text(w.id) || !target || (w.height !== undefined && !finite(w.height, MIN_WINDOW_HEIGHT, 10000))) return undefined;
        if (++count > MAX_WINDOWS) return undefined;
        if ((w.span !== undefined && !finite(w.span, 1, MAX_COLUMNS)) || (w.rows !== undefined && !finite(w.rows, 1, MAX_BANDS)) || (w.row !== undefined && !finite(w.row, 0, MAX_BANDS))) return undefined;
        windows.push({
          id: w.id, target, ...(typeof w.height === "number" ? { height: w.height } : {}),
          ...(typeof w.span === "number" ? { span: Math.floor(w.span) } : {}), ...(typeof w.rows === "number" ? { rows: Math.floor(w.rows) } : {}), ...(typeof w.row === "number" ? { row: Math.floor(w.row) } : {}),
        });
      }
      columns.push({ id: c.id, weight: c.weight, windows });
    }
    views.push({ id: raw.id, kind: raw.kind, name: raw.name, cell, layout: { type: "tiled", columns } });
  }
  // A look that is present must be valid: the server never stores one that is not, so a bad one is a damaged document.
  const look = input.look === undefined ? undefined : parseLook(input.look);
  if (input.look !== undefined && !look) return undefined;
  return { format: FORMAT, version: VERSION, revision: input.revision as number, views, ...(look ? { look } : {}) };
}
