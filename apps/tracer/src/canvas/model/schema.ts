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

export interface CanvasDocument {
  format: typeof FORMAT;
  version: typeof VERSION;
  revision: number;
  views: DocView[];
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
  return { format: FORMAT, version: VERSION, revision: input.revision as number, views };
}
