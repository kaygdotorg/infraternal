/** One decoder for offline startup and the durable layout journal, so damaged cache data cannot stall mount (D180, D245). */
import { randomUuid } from "../../identifiers";
import { parseDocument, type CanvasDocument } from "./document";
import type { Intent } from "./operations";
export interface Pending { op_id: string; base_revision: number; intent: Intent; revision?: number; sent?: boolean }
export interface Migration { op_id: string; document: CanvasDocument }
export interface LayoutCache { canonical: CanvasDocument; pending: Pending[]; unresolved: Set<string>; migration?: Migration }
export function readLayoutCache(value: unknown): LayoutCache | undefined {
  const legacy = parseDocument(value);
  if (legacy) return { canonical: { format: "infraternal.canvas", version: 1, revision: 0, views: [] }, pending: [], unresolved: new Set(), migration: { op_id: randomUuid(), document: legacy } };
  if (!value || typeof value !== "object" || !("cacheVersion" in value) || value.cacheVersion !== 2) return undefined;
  const cache = value as { canonical?: unknown; document?: unknown; pending?: Pending[]; unresolved?: string[]; migration?: Migration };
  const canonical = parseDocument(cache.canonical);
  if (!canonical || !parseDocument(cache.document)) return undefined;
  return {
    canonical,
    pending: Array.isArray(cache.pending) && cache.pending.length <= 1024 ? cache.pending : [],
    unresolved: new Set(Array.isArray(cache.unresolved) ? cache.unresolved.filter((id) => typeof id === "string") : []),
    ...(cache.migration && typeof cache.migration.op_id === "string" && parseDocument(cache.migration.document) ? { migration: cache.migration } : {}),
  };
}
