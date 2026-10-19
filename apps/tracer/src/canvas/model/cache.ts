/** One decoder for offline startup and the durable layout journal, so damaged cache data cannot stall mount (D180, D245). */
import { LayoutJournal, type JournalState } from "./journal";
import { isCanonicalUuid, randomUuid } from "../../identifiers";
import { parseDocument } from "./schema";
import type { Pending, Migration } from "./journal";
export type LayoutCache = JournalState;
export function readLayoutCache(value: unknown): LayoutCache | undefined {
  const legacy = parseDocument(value);
  if (legacy) return { canonical: { format: "infraternal.canvas", version: 1, revision: 0, views: [] }, pending: [], unresolved: new Set(), migration: { op_id: randomUuid(), document: legacy } };
  if (!value || typeof value !== "object" || !("cacheVersion" in value) || value.cacheVersion !== 2) return undefined;
  const cache = value as { canonical?: unknown; document?: unknown; pending?: Pending[]; unresolved?: string[]; migration?: Migration };
  const canonical = parseDocument(cache.canonical);
  if (!canonical || !parseDocument(cache.document)) return undefined;
  if (cache.pending !== undefined && !Array.isArray(cache.pending)) return undefined;
  const pending = cache.pending ?? [];
  const migration = cache.migration;
  if (migration && (typeof migration.op_id !== "string" || !parseDocument(migration.document) || migration.revision !== undefined && (!Number.isSafeInteger(migration.revision) || migration.revision < 0))) return undefined;
  // A journal is replayed before mount as well as before offline identity is accepted. Never let
  // damaged local retry data throw while drawing or turn a missing reference into a live session.
  try {
    for (const p of pending) {
      if (!p || !isCanonicalUuid(p.op_id) || !Number.isSafeInteger(p.base_revision) || p.base_revision < 0 || !p.intent || typeof p.intent !== "object") return undefined;
      if ((p.intent.type === "open" || p.intent.type === "split") && (!p.intent.window || typeof p.intent.window.id !== "string")) return undefined;
      if (p.revision !== undefined && (!Number.isSafeInteger(p.revision) || p.revision < 0)) return undefined;
    }
    if (!parseDocument(new LayoutJournal({ canonical, pending, unresolved: new Set(), ...(migration ? { migration } : {}) }).current())) return undefined;
  } catch { return undefined; }
  return {
    canonical,
    pending,
    unresolved: new Set(Array.isArray(cache.unresolved) ? cache.unresolved.filter((id) => typeof id === "string") : []),
    ...(migration ? { migration } : {}),
  };
}

/** Persist the same projection the live journal paints, together with immutable retry metadata. */
export function layoutCacheValue(journal: LayoutJournal): unknown {
  return { cacheVersion: 2, canonical: journal.canonical, document: journal.current(), pending: journal.pending, unresolved: [...journal.unresolved], ...(journal.migration ? { migration: journal.migration } : {}) };
}
