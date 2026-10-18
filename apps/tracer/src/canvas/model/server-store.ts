/** Account layout subscription, durable retry journal and drawing cache (D178, D183, D245, D248). */
import { canvasKey } from "../../account-storage";
import { parseDocument, type CanvasDocument } from "./document";
import { edits, reduce, type Intent, type SplitEdit } from "./operations";
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
  private canonical = empty();
  private presented = empty();
  private pending: Pending[] = [];
  private migration: Migration | undefined;
  private cached = false;
  private initialized = false;
  private ready = false;
  private disposed = false;
  private busy = false;
  private epoch = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly listeners = new Set<(doc: CanvasDocument) => void>();
  private readonly key: string;
  private readonly off: () => void;
  private loaded: (() => void) | undefined;
  private readonly first: Promise<void>;

  constructor(private readonly transport: LayoutTransport, account: string, private readonly refused: () => void = () => {}) {
    this.key = canvasKey(account);
    this.first = new Promise((resolve) => { this.loaded = resolve; });
    try {
      const value: unknown = JSON.parse(localStorage.getItem(this.key) ?? "null");
      const legacy = parseDocument(value);
      if (legacy) { this.migration = { op_id: crypto.randomUUID(), document: legacy }; this.presented = legacy; this.cached = true; }
      else if (value && typeof value === "object" && "cacheVersion" in value && value.cacheVersion === 2) {
        const cache = value as { canonical?: unknown; document?: unknown; pending?: Pending[]; migration?: Migration; initialized?: boolean };
        const canonical = parseDocument(cache.canonical), document = parseDocument(cache.document);
        if (canonical && document) {
          this.canonical = canonical; this.presented = document; this.cached = true; this.initialized = cache.initialized === true;
          if (Array.isArray(cache.pending) && cache.pending.length <= 1024) this.pending = cache.pending;
          if (cache.migration && typeof cache.migration.op_id === "string" && parseDocument(cache.migration.document)) this.migration = cache.migration;
        }
      }
    } catch { /* damaged or unavailable storage: wait for canonical server state */ }
    this.off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.event(event), () => {
      this.ready = false; this.busy = false; this.epoch++;
    });
  }
  async load(): Promise<CanvasDocument | undefined> {
    if (!this.cached) await this.first;
    return this.presented.views.length ? structuredClone(this.presented) : undefined;
  }
  /** Record each completed edit immediately; only cache serialization is coalesced. */
  async save(doc: CanvasDocument, splits?: ReadonlyMap<string, SplitEdit>, before?: CanvasDocument): Promise<void> {
    if (this.disposed) return;
    for (const intent of edits(before ?? this.presented, doc, splits)) this.pending.push({ op_id: crypto.randomUUID(), base_revision: this.canonical.revision, intent });
    this.presented = structuredClone(doc);
    this.checkpoint(); this.pump();
  }
  current(): CanvasDocument { const doc = structuredClone(this.canonical); for (const p of this.pending) reduce(doc, p.intent); return doc; }
  subscribe(listener: (doc: CanvasDocument) => void): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  private event(event: Record<string, unknown>): void {
    if (this.disposed || !Number.isSafeInteger(event.revision) || Number(event.revision) < this.canonical.revision) return;
    if (event.type === "canvas.layout.snapshot") {
      const document = parseDocument(event.document);
      if (!document || document.revision !== event.revision) return;
      this.canonical = document; this.initialized = event.initialized === true; this.ready = true;
    } else if (event.type === "canvas.layout.operation") {
      if (event.revision === this.canonical.revision) return;
      // Never apply a partial history. A fresh subscription obtains an atomic snapshot on reconnect.
      if (event.revision !== this.canonical.revision + 1 || !event.intent || typeof event.intent !== "object") return;
      if (!event.noop) reduce(this.canonical, event.intent as Intent);
      this.canonical.revision = Number(event.revision);
      this.pending = this.pending.filter((p) => p.op_id !== event.op_id);
    } else return;
    this.pending = this.pending.filter((p) => p.revision === undefined || p.revision > this.canonical.revision);
    this.publish(); this.loaded?.(); this.loaded = undefined; this.pump();
  }
  private publish(): void {
    const document = structuredClone(this.canonical);
    for (const p of this.pending) reduce(document, p.intent);
    // A legacy document stays drawable and intact until its migration is acknowledged.
    this.presented = !this.initialized && this.migration ? structuredClone(this.migration.document) : document;
    this.checkpoint();
    for (const listener of this.listeners) listener(structuredClone(this.presented));
  }
  private pump(): void {
    if (this.disposed || !this.ready || this.busy || this.transport.isWelcomed === false) return;
    const migration = this.migration;
    const operation = this.pending.find((p) => p.revision === undefined);
    if (!migration && !operation) return;
    this.busy = true;
    const epoch = this.epoch;
    const action = migration ? "canvas.layout.initialize" : "canvas.layout.apply";
    const input = migration ? { ...migration } : { op_id: operation!.op_id, base_revision: operation!.base_revision, intent: operation!.intent };
    void this.transport.call(action, input).then((result) => {
      if (this.disposed || epoch !== this.epoch) return;
      if (!Number.isSafeInteger(result.revision)) { this.busy = false; this.ready = false; this.refused(); return; }
      if (migration) { this.migration = undefined; this.initialized = true; }
      else operation!.revision = Number(result.revision);
      this.pending = this.pending.filter((p) => p.revision === undefined || p.revision > this.canonical.revision);
      this.busy = false; this.publish(); this.pump();
    }, () => {
      if (this.disposed || epoch !== this.epoch) return;
      // Keep the identical input for retry after the next snapshot, including its original base revision.
      this.busy = false; this.ready = false; this.checkpoint(); this.refused();
    });
  }
  private checkpoint(): void {
    if (this.timer !== undefined || this.disposed) return;
    this.timer = setTimeout(() => { this.timer = undefined; this.flush(); }, 300);
  }
  flush(): void {
    if (this.disposed) return;
    clearTimeout(this.timer); this.timer = undefined;
    try { localStorage.setItem(this.key, JSON.stringify({ cacheVersion: 2, canonical: this.canonical, document: this.presented, initialized: this.initialized, pending: this.pending, ...(this.migration ? { migration: this.migration } : {}) })); } catch { /* a storage quota cannot block input or the server */ }
  }
  dispose(): void { this.flush(); this.disposed = true; clearTimeout(this.timer); this.epoch++; this.off(); this.listeners.clear(); this.loaded?.(); }
}
