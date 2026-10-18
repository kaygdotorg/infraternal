/** Account layout subscription, durable retry journal and drawing cache (D178, D183, D245, D248). */
import { randomUuid } from "../../identifiers";
import { canvasKey, readStoredJson, writeStoredJson } from "../../account-storage";
import { documentWindows as windows, parseDocument, type CanvasDocument } from "./document";
import { edits, reduce, type Intent, type LayoutEdit } from "./operations";
import { readLayoutCache, type Pending, type Migration } from "./cache";
import type { CanvasStore } from "./store";

export interface LayoutTransport {
  readonly isWelcomed?: boolean;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  subscribe(filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): () => void;
}
const empty = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [] });

export class ServerCanvasStore implements CanvasStore {
  readonly acceptsPendingReferences = true;
  #unresolved = new Set<string>();
  #canonical = empty();
  #pending: Pending[] = [];
  #migration: Migration | undefined;
  #cached = false;
  #initialized = false;
  #ready = false;
  #disposed = false;
  readonly #inflight = new Set<string>();
  #epoch = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  readonly #listeners = new Set<(doc: CanvasDocument) => void>();
  readonly #key: string;
  readonly #off: () => void;
  #loaded: (() => void) | undefined;
  readonly #first: Promise<void>;

  constructor(private readonly transport: LayoutTransport, account: string, private readonly refused: () => void = () => {}) {
    this.#key = canvasKey(account);
    this.#first = new Promise((resolve) => { this.#loaded = resolve; });
    const cache = readLayoutCache(readStoredJson(this.#key));
    if (cache) {
      this.#canonical = cache.canonical; this.#pending = cache.pending; this.#unresolved = cache.unresolved;
      this.#migration = cache.migration; this.#cached = true; this.#initialized = cache.canonical.revision > 0;
    }
    this.#off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.#event(event), () => {
      this.#ready = false; this.#inflight.clear(); this.#epoch++;
    });
  }
  async load(): Promise<CanvasDocument | undefined> {
    if (!this.#cached) await this.#first;
    return this.#cached || this.#initialized || this.current().views.length ? this.current() : undefined;
  }
  /** Record each completed edit immediately; only cache serialization is coalesced. */
  unresolvedWindow(id: string): boolean { return this.#unresolved.has(id); }
  async save(doc: CanvasDocument, hints?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved: ReadonlySet<string> = new Set()): Promise<void> {
    if (this.#disposed) return;
    const previous = structuredClone(before ?? this.current());
    const live = new Map(windows(doc).map((w) => [w.id, w]));
    // Unsatisfied references belong only to the local journal. Complete an unsent birth in place;
    // a sent request is immutable because its operation ID must always identify the same input.
    for (const id of this.#unresolved) {
      if (unresolved.has(id)) continue;
      const window = live.get(id);
      if (window) for (const p of this.#pending) {
        if (!p.sent && (p.intent.type === "open" || p.intent.type === "split") && p.intent.window.id === id) {
          p.intent.window.target = structuredClone(window.target);
          for (const old of windows(previous)) if (old.id === id) old.target = structuredClone(window.target);
        }
      }
    }
    const cancelled = this.#pending.some((p) => !p.sent && (p.intent.type === "open" || p.intent.type === "split") && this.#unresolved.has(p.intent.window.id) && !live.has(p.intent.window.id));
    this.#unresolved = new Set(unresolved);
    let baseline = previous;
    if (cancelled) {
      // Removing an uncreated shell also removes its dependency. Rebuild only the unsent suffix,
      // so surviving children become independent opens and no placeholder can reach the server.
      this.#pending = this.#pending.filter((p) => p.sent);
      baseline = this.current();
    }
    for (const intent of edits(baseline, doc, cancelled ? undefined : hints)) this.#pending.push({ op_id: randomUuid(), base_revision: this.#canonical.revision, intent });
    this.#checkpoint(); this.#pump();
  }
  current(): CanvasDocument {
    const doc = structuredClone(this.#migration && (!this.#initialized || this.#migration.revision !== undefined && this.#canonical.revision < this.#migration.revision) ? this.#migration.document : this.#canonical);
    for (const p of this.#pending) reduce(doc, p.intent);
    return doc;
  }
  subscribe(listener: (doc: CanvasDocument) => void): () => void { this.#listeners.add(listener); return () => this.#listeners.delete(listener); }
  #event(event: Record<string, unknown>): void {
    if (this.#disposed || !Number.isSafeInteger(event.revision) || (event.type !== "canvas.layout.snapshot" || this.#ready) && Number(event.revision) < this.#canonical.revision) return;
    if (event.type === "canvas.layout.snapshot") {
      const document = parseDocument(event.document);
      if (!document || document.revision !== event.revision) return;
      this.#canonical = document; this.#initialized = event.initialized === true; this.#ready = true;
    } else if (event.type === "canvas.layout.operation") {
      if (event.revision === this.#canonical.revision) return;
      // Never apply a partial history. A fresh subscription obtains an atomic snapshot on reconnect.
      if (event.revision !== this.#canonical.revision + 1 || !event.intent || typeof event.intent !== "object") return;
      if (!event.noop) reduce(this.#canonical, event.intent as Intent);
      this.#canonical.revision = Number(event.revision);
      this.#pending = this.#pending.filter((p) => p.op_id !== event.op_id);
    } else return;
    this.#pending = this.#pending.filter((p) => p.revision === undefined || p.revision > this.#canonical.revision);
    if (this.#migration?.revision !== undefined && this.#migration.revision <= this.#canonical.revision) this.#migration = undefined;
    this.#publish(); this.#loaded?.(); this.#loaded = undefined; this.#pump();
  }
  #publish(): void {
    const document = this.current();
    this.#checkpoint();
    for (const listener of this.#listeners) listener(structuredClone(document));
  }
  #pump(): void {
    if (this.#disposed || !this.#ready || this.#inflight.size >= 4 || this.transport.isWelcomed === false) return;
    if (this.#migration?.revision !== undefined) return;
    const migration = this.#migration;
    const operation = this.#pending.find((p) => p.revision === undefined && !this.#inflight.has(p.op_id));
    if (!migration && !operation) return;
    if (!migration && operation && (operation.intent.type === "open" || operation.intent.type === "split") && this.#unresolved.has(operation.intent.window.id)) return;
    if (operation && !migration) operation.sent = true;
    const id = migration?.op_id ?? operation!.op_id;
    if (this.#inflight.has(id)) return;
    this.#inflight.add(id);
    const epoch = this.#epoch;
    const action = migration ? "canvas.layout.initialize" : "canvas.layout.apply";
    const input = migration ? { ...migration } : { op_id: operation!.op_id, base_revision: operation!.base_revision, intent: operation!.intent };
    void this.transport.call(action, input).then((result) => {
      if (this.#disposed || epoch !== this.#epoch) return;
      this.#inflight.delete(id);
      if (!Number.isSafeInteger(result.revision)) { this.#ready = false; this.refused(); return; }
      if (migration) {
        migration.revision = Number(result.revision); this.#initialized = true;
        if (migration.revision <= this.#canonical.revision) this.#migration = undefined;
      }
      else operation!.revision = Number(result.revision);
      const count = this.#pending.length;
      this.#pending = this.#pending.filter((p) => p.revision === undefined || p.revision > this.#canonical.revision);
      // The ordered event usually paints first. Its receipt changes journal metadata only.
      if (migration || this.#pending.length !== count) this.#publish(); else this.#checkpoint();
      this.#pump();
    }, () => {
      if (this.#disposed || epoch !== this.#epoch) return;
      // Keep the identical input for retry after the next snapshot, including its original base revision.
      this.#inflight.delete(id); this.#ready = false; this.#checkpoint(); this.refused();
    });
    // Bounded pipelining preserves socket order without making each independent edit wait for the previous RTT.
    if (!migration) this.#pump();
  }
  #checkpoint(): void {
    if (this.#timer !== undefined || this.#disposed) return;
    this.#timer = setTimeout(() => { this.#timer = undefined; this.flush(); }, 300);
  }
  flush(): void {
    if (this.#disposed) return;
    clearTimeout(this.#timer); this.#timer = undefined;
    writeStoredJson(this.#key, { cacheVersion: 2, canonical: this.#canonical, document: this.current(), pending: this.#pending, unresolved: [...this.#unresolved], ...(this.#migration ? { migration: this.#migration } : {}) });
  }
  dispose(): void { this.flush(); this.#disposed = true; this.#epoch++; this.#off(); this.#listeners.clear(); this.#loaded?.(); }
}
