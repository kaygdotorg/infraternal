/** One decoder for offline startup and the durable layout journal, so damaged cache data cannot stall mount (D180, D245). */
import { reduce } from "./reducer";
import { isCanonicalUuid, randomUuid } from "../../identifiers";
import { parseDocument, type CanvasDocument } from "./document";
import type { Intent } from "./operations";
export interface Pending { op_id: string; base_revision: number; intent: Intent; revision?: number; sent?: boolean }
export interface Migration { op_id: string; document: CanvasDocument; revision?: number }
export interface LayoutCache { canonical: CanvasDocument; pending: Pending[]; unresolved: Set<string>; migration?: Migration }
export function readLayoutCache(value: unknown): LayoutCache | undefined {
  const legacy = parseDocument(value);
  if (legacy) return { canonical: { format: "infraternal.canvas", version: 1, revision: 0, views: [] }, pending: [], unresolved: new Set(), migration: { op_id: randomUuid(), document: legacy } };
  if (!value || typeof value !== "object" || !("cacheVersion" in value) || value.cacheVersion !== 2) return undefined;
  const cache = value as { canonical?: unknown; document?: unknown; pending?: Pending[]; unresolved?: string[]; migration?: Migration };
  const canonical = parseDocument(cache.canonical);
  if (!canonical || !parseDocument(cache.document)) return undefined;
  if (cache.pending !== undefined && (!Array.isArray(cache.pending) || cache.pending.length > 1024)) return undefined;
  const pending = cache.pending ?? [];
  const migration = cache.migration;
  if (migration && (typeof migration.op_id !== "string" || !parseDocument(migration.document) || migration.revision !== undefined && (!Number.isSafeInteger(migration.revision) || migration.revision < 0))) return undefined;
  // A journal is replayed before mount as well as before offline identity is accepted. Never let
  // damaged local retry data throw while drawing or turn a missing reference into a live session.
  try {
    const projected = structuredClone(canonical);
    for (const p of pending) {
      if (!p || !isCanonicalUuid(p.op_id) || !Number.isSafeInteger(p.base_revision) || p.base_revision < 0 || !p.intent || typeof p.intent !== "object") return undefined;
      if ((p.intent.type === "open" || p.intent.type === "split") && (!p.intent.window || typeof p.intent.window.id !== "string")) return undefined;
      if (p.revision !== undefined && (!Number.isSafeInteger(p.revision) || p.revision < 0)) return undefined;
      reduce(projected, p.intent);
    }
    if (!parseDocument(projected)) return undefined;
  } catch { return undefined; }
  return {
    canonical,
    pending,
    unresolved: new Set(Array.isArray(cache.unresolved) ? cache.unresolved.filter((id) => typeof id === "string") : []),
    ...(migration ? { migration } : {}),
  };
}
