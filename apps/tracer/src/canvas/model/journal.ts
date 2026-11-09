/** Per-tab optimistic intents. Only server receipts/events establish identity; snapshots never prove an edit committed (D312). */
import { randomUuid } from "../../identifiers";
import { documentWindows as windows, parseDocument, type CanvasDocument } from "./schema";
import { edits, reduce, type Intent, type LayoutEdit } from "./operations";
export interface Pending { op_id: string; base_revision: number; intent: Intent; revision?: number; sent?: boolean; held?: boolean }
export interface Migration { op_id: string; document: CanvasDocument; revision?: number }
export interface JournalState { canonical: CanvasDocument; pending: Pending[]; unresolved: Set<string>; migration?: Migration }
/** Backpressure is explicit; the tab never silently drops an unconfirmed identity. */
export class LayoutQueueFull extends Error {}
const entryBytes = (intent: Intent): number => JSON.stringify(intent).length * 2 + 256;
/** Only adjacent unsent changes to exactly the same fields can share an identity. */
function field(intent: Intent): string | undefined {
  if (!["view.update", "target", "resize", "weight", "pin"].includes(intent.type)) return undefined;
  const row = intent as unknown as Record<string, unknown>;
  // Tuple encoding preserves identifier boundaries even when an identifier contains a separator.
  return JSON.stringify([intent.type, row.view_id, row.window_id, row.column_id, row.node_id, Object.keys(row).sort()]);
}
/** The tab's ordered list of unconfirmed canvas edits over the last server-confirmed document; the visible document is that canonical state with these edits replayed on top. */
export class LayoutJournal {
  #queuedBytes = 0;

  #projection: CanvasDocument | undefined;
  #ready = false;
  readonly #inflight = new Set<string>();
  epoch = 0;
  canonical: CanvasDocument;
  pending: Pending[];
  unresolved: Set<string>;
  migration: Migration | undefined;
  initialized: boolean;
  constructor(state?: JournalState, private readonly maxPendingBytes = 32 * 1024 * 1024) {
    this.canonical = state?.canonical ?? { format: "infraternal.canvas", version: 1, revision: 0, views: [] };
    this.pending = state?.pending ?? []; this.unresolved = state?.unresolved ?? new Set(); this.migration = state?.migration;
    this.#queuedBytes = this.pending.reduce((total, p) => total + entryBytes(p.intent), 0);
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
      this.#retain((p) => p.op_id !== event.op_id);
    } else return false;
    this.#prune(); return true;
  }
  clear(): void { this.restart(); this.pending = []; this.#queuedBytes = 0; this.unresolved.clear(); this.migration = undefined; this.canonical = { format: "infraternal.canvas", version: 1, revision: 0, views: [] }; this.#projection = undefined; }
  restart(): void { this.#ready = false; this.#inflight.clear(); this.epoch++; }
  /** Reserve a bounded ready request; sent inputs remain immutable across reconnects. */
  next(): Pending | Migration | undefined {
    if (!this.#ready || this.#inflight.size >= 4) return undefined;
    let entry: Pending | Migration | undefined;
    if (this.migration) entry = this.migration.revision === undefined && !this.#inflight.has(this.migration.op_id) ? this.migration : undefined;
    else {
      const op = this.pending.find((p) => p.revision === undefined && !this.#inflight.has(p.op_id));
      if (op && (op.intent.type === "open" || op.intent.type === "split") && this.unresolved.has(op.intent.window.id)) return undefined;
      // A whole look is a compare-and-set on the last look. One sent while another of ours is still unacknowledged would
      // carry the same base and be refused, losing the later pick, so it waits for the acknowledgement and is rebased there.
      if (op && op.intent.type === "look.set" && this.pending.some((p) => p !== op && p.intent.type === "look.set" && p.revision === undefined && this.#inflight.has(p.op_id))) return undefined;
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
    else this.#retain((p) => p.op_id !== entry.op_id);
    this.#projection = undefined;
    const live = new Set(windows(this.current()).map((w) => w.id));
    this.unresolved = new Set([...this.unresolved].filter((id) => live.has(id)));
    return true;
  }
  /** Records the server's receipt revision for a sent edit or migration. Returns whether the visible document may change. An accepted `look.set` also rebases the unsent looks queued behind it. */
  acknowledge(operation: Pending | Migration, revision: number, migration: boolean): boolean {
    if ("intent" in operation && !this.pending.includes(operation) || "document" in operation && this.migration !== operation) return false;
    const revealed = "intent" in operation && operation.held === true && revision > this.canonical.revision;
    this.#projection = undefined;
    operation.revision = revision;
    // Our own accepted look is the newest look on the server, so a look queued behind it is based on it: the server
    // refuses a look written from before another look, and that must not hit this tab's own quick successive edits.
    if ("intent" in operation && operation.intent.type === "look.set") {
      for (const next of this.pending) if (next !== operation && !next.sent && next.intent.type === "look.set" && next.base_revision < revision) next.base_revision = revision;
    }
    if ("intent" in operation) delete operation.held;
    if (migration) this.initialized = true;
    const changed = this.#prune(); return migration || changed || revealed;
  }
  #retain(keep: (entry: Pending) => boolean): void {
    this.pending = this.pending.filter((p) => { if (keep(p)) return true; this.#queuedBytes -= entryBytes(p.intent); return false; });
  }
  #prune(): boolean {
    const count = this.pending.length;
    this.#retain((p) => p.revision === undefined || p.revision > this.canonical.revision);
    if (this.migration?.revision !== undefined && this.migration.revision <= this.canonical.revision) this.migration = undefined;
    return this.pending.length !== count;
  }
  capture(doc: CanvasDocument, hints?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved: ReadonlySet<string> = new Set()): boolean {
    let projection = this.current();
    const previous = structuredClone(before ?? projection);
    const live = new Map(windows(doc).map((w) => [w.id, w]));
    const cancelled = this.unresolved.size > 0 && this.pending.some((p) => !p.sent && (p.intent.type === "open" || p.intent.type === "split") && this.unresolved.has(p.intent.window.id) && !live.has(p.intent.window.id));
    // Stage reference completion and suffix rebuilding before admission. Rejection must preserve
    // every previously accepted identity, dependency and byte, including unresolved births.
    const retained = cancelled ? this.pending.filter((p) => p.sent) : this.pending;
    const patches: Array<{ entry: Pending; intent: Intent }> = [];
    for (const id of this.unresolved) {
      if (unresolved.has(id)) continue;
      const window = live.get(id);
      if (window) for (const p of retained) {
        if (!p.sent && (p.intent.type === "open" || p.intent.type === "split") && p.intent.window.id === id) {
          const intent = structuredClone(p.intent); intent.window.target = structuredClone(window.target);
          patches.push({ entry: p, intent });
          for (const value of [previous, projection]) for (const old of windows(value)) if (old.id === id) old.target = structuredClone(window.target);
        }
      }
    }
    let baseline = previous;
    if (cancelled) { baseline = this.#project(retained); projection = structuredClone(baseline); }
    // Accepted inputs own their values; the canvas may mutate its next drawing in place.
    const intents = edits(baseline, doc, cancelled ? undefined : hints).map((intent) => structuredClone(intent));
    const last = retained.at(-1), next = intents[0];
    // Two looks in a row that have not left yet are one change: only the latest pick matters.
    const lookOverLook = next?.type === "look.set" && last?.intent.type === "look.set";
    const coalesced = !cancelled && intents.length === 1 && last && !last.sent && next && (lookOverLook || field(next) !== undefined && field(last.intent) === field(next));
    const retainedBytes = cancelled ? retained.reduce((total, p) => total + entryBytes(p.intent), 0) : this.#queuedBytes;
    const patchBytes = patches.reduce((total, p) => total + entryBytes(p.intent) - entryBytes(p.entry.intent), 0);
    const bytes = intents.reduce((total, intent) => total + entryBytes(intent), 0) - (coalesced ? entryBytes(last.intent) : 0);
    if (retainedBytes + patchBytes + bytes > this.maxPendingBytes) throw new LayoutQueueFull("This tab has too many unsaved layout changes. Connect before making more.");
    this.pending = retained; this.unresolved = new Set(unresolved);
    this.#queuedBytes = retainedBytes + patchBytes + bytes;
    for (const patch of patches) patch.entry.intent = patch.intent;
    if (coalesced) { last.intent = next; reduce(projection, next); }
    else for (const intent of intents) { this.pending.push({ op_id: randomUuid(), base_revision: this.canonical.revision, intent }); reduce(projection, intent); }
    this.#projection = projection;
    return patches.length > 0 || cancelled || intents.length > 0;
  }
  #project(pending: readonly Pending[]): CanvasDocument {
    const doc = structuredClone(this.migration && (!this.initialized || this.migration.revision !== undefined && this.canonical.revision < this.migration.revision) ? this.migration.document : this.canonical);
    for (const p of pending) if (!p.held) reduce(doc, p.intent);
    return doc;
  }
  current(): CanvasDocument {
    if (this.#projection) return structuredClone(this.#projection);
    const doc = this.#project(this.pending);
    this.#projection = doc;
    return structuredClone(doc);
  }
}
