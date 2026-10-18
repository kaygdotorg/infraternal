/** Account layout subscription, durable retry journal and drawing cache (D178, D183, D245, D248). */
import { canvasKey, readStoredJson, createStoredJsonCache } from "../../account-storage";
import type { CanvasDocument } from "./schema";
import type { LayoutEdit } from "./operations";
import { layoutCacheValue, readLayoutCache } from "./cache";
import { LayoutJournal } from "./journal";
import type { CanvasStore } from "./store";

export interface LayoutTransport {
  readonly isWelcomed?: boolean;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  subscribe(filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): () => void;
}
export class ServerCanvasStore implements CanvasStore {
  readonly acceptsPendingReferences = true;
  readonly #journal: LayoutJournal;
  #cached = false;
  #disposed = false;
  readonly #cache: ReturnType<typeof createStoredJsonCache>;
  readonly #off: () => void;
  #loaded: (() => void) | undefined;
  readonly #first: Promise<void>;

  constructor(private readonly transport: LayoutTransport, account: string, private readonly refused: () => void = () => {}) {
    const key = canvasKey(account);
    this.#first = new Promise((resolve) => { this.#loaded = resolve; });
    const cache = readLayoutCache(readStoredJson(key));
    this.#journal = new LayoutJournal(cache); this.#cached = cache !== undefined;
    this.#cache = createStoredJsonCache(key, () => layoutCacheValue(this.#journal));
    this.#off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.#event(event), () => {
      this.#journal.restart();
    });
  }
  async load(): Promise<CanvasDocument | undefined> {
    if (!this.#cached) await this.#first;
    return this.#cached || this.#journal.initialized || this.current().views.length ? this.current() : undefined;
  }
  /** A placeholder drawing ID must never be used to attach a terminal. */
  unresolvedWindow(id: string): boolean { return this.#journal.unresolved.has(id); }
  /** Capture synchronously; network receipts never gate input. */
  async save(doc: CanvasDocument, hints?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved: ReadonlySet<string> = new Set()): Promise<void> {
    if (this.#disposed) return;
    if (this.#journal.capture(doc, hints, before, unresolved)) this.#publish(); else this.#cache.schedule();
    this.#pump();
  }
  current(): CanvasDocument { return this.#journal.current(); }
  subscribe(listener: () => void): () => void { return this.#cache.subscribe(listener); }
  #event(event: Record<string, unknown>): void {
    if (this.#disposed || !this.#journal.accept(event)) return;
    this.#publish(); this.#loaded?.(); this.#loaded = undefined; this.#pump();
  }
  #publish(): void { this.#cache.changed(); }
  #pump(): void {
    if (this.#disposed || this.transport.isWelcomed === false) return;
    const entry = this.#journal.next(); if (!entry) return;
    const migration = "document" in entry;
    const epoch = this.#journal.epoch;
    const action = migration ? "canvas.layout.initialize" : "canvas.layout.apply";
    const input = "document" in entry ? { op_id: entry.op_id, document: entry.document } : { op_id: entry.op_id, base_revision: entry.base_revision, intent: entry.intent };
    void this.transport.call(action, input).then((result) => {
      if (this.#disposed || !this.#journal.release(entry, epoch)) return;
      if (!Number.isSafeInteger(result.revision)) { this.#journal.fail(entry, epoch); this.refused(); return; }
      // The ordered event usually paints first. Its receipt changes journal metadata only.
      if (this.#journal.acknowledge(entry, Number(result.revision), migration)) this.#publish(); else this.#cache.schedule();
      this.#pump();
    }, () => {
      if (this.#disposed || !this.#journal.fail(entry, epoch)) return;
      // Keep the identical input for retry after the next snapshot, including its original base revision.
      this.#cache.schedule(); this.refused();
    });
    // Bounded pipelining preserves socket order without making each independent edit wait for the previous RTT.
    if (!migration) this.#pump();
  }
  flush(): void { this.#cache.flush(); }
  dispose(): void { this.#cache.dispose(); this.#disposed = true; this.#journal.restart(); this.#off(); this.#loaded?.(); }
}
