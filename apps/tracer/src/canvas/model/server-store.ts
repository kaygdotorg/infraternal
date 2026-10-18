/** Account layout subscription, durable retry journal and drawing cache (D178, D183, D245, D248). */
import { randomUuid } from "../../identifiers";
import { canvasKey } from "../../account-storage";
import { parseDocument, type CanvasDocument } from "./document";
import type { Intent, LayoutEdit } from "./operations.on-demand";
import { onDemand } from "../../on-demand";
import type { CanvasStore } from "./store";

export interface LayoutTransport {
  readonly isWelcomed?: boolean;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  subscribe(filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): () => void;
}
interface Pending { op_id: string; base_revision: number; intent: Intent; revision?: number }
interface Migration { op_id: string; document: CanvasDocument }
const empty = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [] });

export class ServerCanvasStore implements CanvasStore {
  #canonical = empty();
  #presented = empty();
  #pending: Pending[] = [];
  #migration: Migration | undefined;
  #cached = false;
  #initialized = false;
  #ready = false;
  #disposed = false;
  #busy = false;
  #epoch = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  readonly #listeners = new Set<(doc: CanvasDocument) => void>();
  readonly #key: string;
  readonly #off: () => void;
  #engine: typeof import("./operations.on-demand") | undefined;
  #loading: Promise<typeof import("./operations.on-demand")> | undefined;
  #work: Promise<void> = Promise.resolve();
  #loadEngine(): Promise<typeof import("./operations.on-demand")> {
    return this.#loading ??= onDemand(() => import("./operations.on-demand")).then((engine) => { this.#engine = engine; return engine; }, (error: unknown) => { this.#loading = undefined; throw error; });
  }
  #enqueue(run: () => void | Promise<void>): Promise<void> {
    this.#work = this.#work.then(() => { if (!this.#disposed) return run(); }).catch(() => { if (!this.#disposed) this.refused(); });
    return this.#work;
  }
  #loaded: (() => void) | undefined;
  readonly #first: Promise<void>;

  constructor(private readonly transport: LayoutTransport, account: string, private readonly refused: () => void = () => {}) {
    this.#key = canvasKey(account);
    this.#first = new Promise((resolve) => { this.#loaded = resolve; });
    try {
      const value: unknown = JSON.parse(localStorage.getItem(this.#key) ?? "null");
      const legacy = parseDocument(value);
      if (legacy) { this.#migration = { op_id: randomUuid(), document: legacy }; this.#presented = legacy; this.#cached = true; }
      else if (value && typeof value === "object" && "cacheVersion" in value && value.cacheVersion === 2) {
        const cache = value as { canonical?: unknown; document?: unknown; pending?: Pending[]; migration?: Migration };
        const canonical = parseDocument(cache.canonical), document = parseDocument(cache.document);
        if (canonical && document) {
          this.#canonical = canonical; this.#presented = document; this.#cached = true; this.#initialized = canonical.revision > 0;
          if (Array.isArray(cache.pending) && cache.pending.length <= 1024) this.#pending = cache.pending;
          if (cache.migration && typeof cache.migration.op_id === "string" && parseDocument(cache.migration.document)) this.#migration = cache.migration;
        }
      }
    } catch { /* damaged or unavailable storage: wait for canonical server state */ }
    this.#off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.#event(event), () => {
      this.#ready = false; this.#busy = false; this.#epoch++;
    });
  }
  async load(): Promise<CanvasDocument | undefined> {
    if (!this.#cached) await this.#first;
    return this.#cached || this.#initialized || this.#presented.views.length ? structuredClone(this.#presented) : undefined;
  }
  /** Record each completed edit immediately; only cache serialization is coalesced. */
  /** Warm after first draw; input still uses its optimistic runtime model immediately. */
  prepare(): void { void this.#loadEngine().catch(() => undefined); }
  save(doc: CanvasDocument, splits?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument): Promise<void> {
    const next = structuredClone(doc), previous = before && structuredClone(before), hints = splits && new Map(splits);
    const capture = (): void => {
      if (this.#disposed || !this.#engine) return;
      for (const intent of this.#engine.edits(previous ?? this.#presented, next, hints)) this.#pending.push({ op_id: randomUuid(), base_revision: this.#canonical.revision, intent });
      this.#presented = next;
      this.#checkpoint(); this.#pump();
    };
    // A listener can flush an edit inside a canonical paint. Capture it before deriving that paint's overlay.
    if (this.#engine) { capture(); return Promise.resolve(); }
    return this.#enqueue(async () => { await this.#loadEngine(); capture(); });
  }
  current(): CanvasDocument {
    if (!this.#engine && this.#pending.length) return structuredClone(this.#presented);
    const doc = structuredClone(this.#canonical);
    for (const p of this.#pending) this.#engine?.reduce(doc, p.intent);
    return doc;
  }
  subscribe(listener: (doc: CanvasDocument) => void): () => void { this.#listeners.add(listener); return () => this.#listeners.delete(listener); }
  #event(event: Record<string, unknown>): void {
    const epoch = this.#epoch;
    void this.#enqueue(async () => {
      if (event.type === "canvas.layout.operation" || this.#pending.length) await this.#loadEngine();
      if (!this.#disposed && epoch === this.#epoch) this.#accept(event);
    });
  }
  #accept(event: Record<string, unknown>): void {
    if (this.#disposed || !Number.isSafeInteger(event.revision) || (event.type !== "canvas.layout.snapshot" || this.#ready) && Number(event.revision) < this.#canonical.revision) return;
    if (event.type === "canvas.layout.snapshot") {
      const document = parseDocument(event.document);
      if (!document || document.revision !== event.revision) return;
      this.#canonical = document; this.#initialized = event.initialized === true; this.#ready = true;
    } else if (event.type === "canvas.layout.operation") {
      if (event.revision === this.#canonical.revision) return;
      // Never apply a partial history. A fresh subscription obtains an atomic snapshot on reconnect.
      if (event.revision !== this.#canonical.revision + 1 || !event.intent || typeof event.intent !== "object") return;
      if (!event.noop) this.#engine?.reduce(this.#canonical, event.intent as Intent);
      this.#canonical.revision = Number(event.revision);
      this.#pending = this.#pending.filter((p) => p.op_id !== event.op_id);
    } else return;
    this.#pending = this.#pending.filter((p) => p.revision === undefined || p.revision > this.#canonical.revision);
    this.#publish(); this.#loaded?.(); this.#loaded = undefined; this.#pump();
  }
  #publish(): void {
    const document = this.current();
    // A legacy document stays drawable and intact until its migration is acknowledged.
    this.#presented = !this.#initialized && this.#migration ? structuredClone(this.#migration.document) : document;
    this.#checkpoint();
    for (const listener of this.#listeners) listener(structuredClone(this.#presented));
  }
  #pump(): void {
    if (this.#disposed || !this.#ready || this.#busy || this.transport.isWelcomed === false) return;
    const migration = this.#migration;
    const operation = this.#pending.find((p) => p.revision === undefined);
    if (!migration && !operation) return;
    this.#busy = true;
    const epoch = this.#epoch;
    const action = migration ? "canvas.layout.initialize" : "canvas.layout.apply";
    const input = migration ? { ...migration } : { op_id: operation!.op_id, base_revision: operation!.base_revision, intent: operation!.intent };
    void this.transport.call(action, input).then((result) => this.#enqueue(() => {
      if (this.#disposed || epoch !== this.#epoch) return;
      if (!Number.isSafeInteger(result.revision)) { this.#busy = false; this.#ready = false; this.refused(); return; }
      if (migration) { this.#migration = undefined; this.#initialized = true; }
      else operation!.revision = Number(result.revision);
      this.#pending = this.#pending.filter((p) => p.revision === undefined || p.revision > this.#canonical.revision);
      this.#busy = false; this.#publish(); this.#pump();
    }), () => this.#enqueue(() => {
      if (this.#disposed || epoch !== this.#epoch) return;
      // Keep the identical input for retry after the next snapshot, including its original base revision.
      this.#busy = false; this.#ready = false; this.#checkpoint(); this.refused();
    }));
  }
  #checkpoint(): void {
    if (this.#timer !== undefined || this.#disposed) return;
    this.#timer = setTimeout(() => { this.#timer = undefined; this.flush(); }, 300);
  }
  flush(): void {
    if (this.#disposed) return;
    clearTimeout(this.#timer); this.#timer = undefined;
    try { localStorage.setItem(this.#key, JSON.stringify({ cacheVersion: 2, canonical: this.#canonical, document: this.#presented, pending: this.#pending, ...(this.#migration ? { migration: this.#migration } : {}) })); } catch { /* a storage quota cannot block input or the server */ }
  }
  dispose(): void { this.flush(); this.#disposed = true; this.#epoch++; this.#off(); this.#listeners.clear(); this.#loaded?.(); }
}
