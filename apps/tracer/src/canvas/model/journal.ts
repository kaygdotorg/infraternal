/** Per-tab optimistic intents. Only server receipts/events establish identity; snapshots never prove an edit committed (D312). */
import { randomUuid } from "../../identifiers";
import { documentWindows as windows, parseDocument, type CanvasDocument } from "./schema";
import { edits, reduce, type Intent, type LayoutEdit } from "./operations";
export interface Pending { op_id: string; base_revision: number; intent: Intent; revision?: number; sent?: boolean; held?: boolean }
export interface Migration { op_id: string; document: CanvasDocument; revision?: number }
export interface JournalState { canonical: CanvasDocument; pending: Pending[]; unresolved: Set<string>; migration?: Migration }
export class LayoutJournal {
  #projection: CanvasDocument | undefined;
  #ready = false;
  readonly #inflight = new Set<string>();
  epoch = 0;
  canonical: CanvasDocument;
  pending: Pending[];
  unresolved: Set<string>;
  migration: Migration | undefined;
  initialized: boolean;
  constructor(state?: JournalState) {
    this.canonical = state?.canonical ?? { format: "infraternal.canvas", version: 1, revision: 0, views: [] };
    this.pending = state?.pending ?? []; this.unresolved = state?.unresolved ?? new Set(); this.migration = state?.migration;
    this.initialized = this.canonical.revision > 0;
    this.#prune();
  }
  /** Accept only a contiguous ordered history; a new subscription may replace the cached baseline. */
  accept(event: Record<string, unknown>): boolean {
    if (!Number.isSafeInteger(event.revision) || (event.type !== "canvas.layout.snapshot" || this.#ready) && Number(event.revision) < this.canonical.revision) return false;
    if (event.type === "canvas.layout.snapshot") {
      const document = parseDocument(event.document);
      if (!document || document.revision !== event.revision) return false;
      this.#projection = undefined;
      for (const p of this.pending) if (p.sent && p.revision === undefined) p.held = true;
      this.canonical = document; this.initialized = event.initialized === true; this.#ready = true;
    } else if (event.type === "canvas.layout.operation") {
      if (event.revision !== this.canonical.revision + 1 || !event.intent || typeof event.intent !== "object") return false;
      this.#projection = undefined;
      if (!event.noop) reduce(this.canonical, event.intent as Intent);
      this.canonical.revision = Number(event.revision); this.initialized = true;
      this.pending = this.pending.filter((p) => p.op_id !== event.op_id);
    } else return false;
    this.#prune(); return true;
  }
  restart(): void { this.#ready = false; this.#inflight.clear(); this.epoch++; }
  /** Reserve a bounded ready request; sent inputs remain immutable across reconnects. */
  next(): Pending | Migration | undefined {
    if (!this.#ready || this.#inflight.size >= 4) return undefined;
    let entry: Pending | Migration | undefined;
    if (this.migration) entry = this.migration.revision === undefined && !this.#inflight.has(this.migration.op_id) ? this.migration : undefined;
    else {
      const op = this.pending.find((p) => p.revision === undefined && !this.#inflight.has(p.op_id));
      if (op && (op.intent.type === "open" || op.intent.type === "split") && this.unresolved.has(op.intent.window.id)) return undefined;
      entry = op;
    }
    if (entry) { if ("intent" in entry) entry.sent = true; this.#inflight.add(entry.op_id); }
    return entry;
  }
  release(entry: Pending | Migration, epoch: number): boolean {
    if (epoch !== this.epoch) return false;
    this.#inflight.delete(entry.op_id); return "intent" in entry ? this.pending.includes(entry) : this.migration === entry;
  }
  fail(entry: Pending | Migration, epoch: number): boolean {
    if (!this.release(entry, epoch)) return false;
    this.#ready = false; return true;
  }
  /** A definitive refusal has no server revision and must never be replayed as an optimistic success. */
  refuse(entry: Pending | Migration, epoch: number): boolean {
    if (!this.release(entry, epoch)) return false;
    if ("document" in entry) { if (this.migration === entry) this.migration = undefined; }
    else this.pending = this.pending.filter((p) => p.op_id !== entry.op_id);
    this.#projection = undefined;
    const live = new Set(windows(this.current()).map((w) => w.id));
    this.unresolved = new Set([...this.unresolved].filter((id) => live.has(id)));
    return true;
  }
  acknowledge(operation: Pending | Migration, revision: number, migration: boolean): boolean {
    if ("intent" in operation && !this.pending.includes(operation) || "document" in operation && this.migration !== operation) return false;
    const revealed = "intent" in operation && operation.held === true && revision > this.canonical.revision;
    this.#projection = undefined;
    operation.revision = revision;
    if ("intent" in operation) delete operation.held;
    if (migration) this.initialized = true;
    const changed = this.#prune(); return migration || changed || revealed;
  }
  #prune(): boolean {
    const count = this.pending.length;
    this.pending = this.pending.filter((p) => p.revision === undefined || p.revision > this.canonical.revision);
    if (this.migration?.revision !== undefined && this.migration.revision <= this.canonical.revision) this.migration = undefined;
    return this.pending.length !== count;
  }
  capture(doc: CanvasDocument, hints?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved: ReadonlySet<string> = new Set()): boolean {
    let projection = this.current();
    const previous = structuredClone(before ?? projection);
    let patched = false;
    const live = new Map(windows(doc).map((w) => [w.id, w]));
    // Unsatisfied references belong only to the local journal. Complete an unsent birth in place;
    // a sent request is immutable because its operation ID must always identify the same input.
    for (const id of this.unresolved) {
      if (unresolved.has(id)) continue;
      const window = live.get(id);
      if (window) for (const p of this.pending) {
        if (!p.sent && (p.intent.type === "open" || p.intent.type === "split") && p.intent.window.id === id) {
          p.intent.window.target = structuredClone(window.target); patched = true;
          for (const value of [previous, projection]) for (const old of windows(value)) if (old.id === id) old.target = structuredClone(window.target);
        }
      }
    }
    const cancelled = this.pending.some((p) => !p.sent && (p.intent.type === "open" || p.intent.type === "split") && this.unresolved.has(p.intent.window.id) && !live.has(p.intent.window.id));
    this.unresolved = new Set(unresolved);
    let baseline = previous;
    if (cancelled) {
      // Removing an uncreated shell also removes its dependency. Rebuild only the unsent suffix,
      // so surviving children become independent opens and no placeholder can reach the server.
      this.pending = this.pending.filter((p) => p.sent);
      this.#projection = undefined;
      baseline = this.current(); projection = structuredClone(baseline);
    }
    const intents = edits(baseline, doc, cancelled ? undefined : hints);
    for (const intent of intents) { this.pending.push({ op_id: randomUuid(), base_revision: this.canonical.revision, intent }); reduce(projection, intent); }
    this.#projection = projection;
    return patched || cancelled || intents.length > 0;
  }
  current(): CanvasDocument {
    if (this.#projection) return structuredClone(this.#projection);
    const doc = structuredClone(this.migration && (!this.initialized || this.migration.revision !== undefined && this.canonical.revision < this.migration.revision) ? this.migration.document : this.canonical);
    for (const p of this.pending) if (!p.held) reduce(doc, p.intent);
    this.#projection = doc;
    return structuredClone(doc);
  }
}
