/** Account layout subscription, durable retry journal and drawing cache (D178, D183, D245, D248). */
import { canvasKey, readStoredJson, createStoredJsonCache } from "../../account-storage";
import type { CanvasDocument } from "./schema";
import type { LayoutEdit } from "./operations";
import { layoutCacheValue, readLayoutCache } from "./cache";
import { ActionRefused, type SubscriptionHandle } from "../../connection";
import { LayoutJournal } from "./journal";
import type { CanvasStore } from "./store";

export interface LayoutTransport {
  readonly isWelcomed?: boolean;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  subscribe(filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): SubscriptionHandle;
}
export class ServerCanvasStore implements CanvasStore {
  readonly acceptsPendingReferences = true;
  readonly #journal: LayoutJournal;
  #disposed = false;
  readonly #cache: ReturnType<typeof createStoredJsonCache>;
  readonly #off: SubscriptionHandle;
  #resyncTimer: ReturnType<typeof setTimeout> | undefined;
  #resyncDelay = 250;
  #resyncTarget = 0;
  #loaded: (() => void) | undefined;
  readonly #first: Promise<void>;

  constructor(private readonly transport: LayoutTransport, account: string, private readonly refused: (definitive?: boolean) => void = () => {}) {
    const key = canvasKey(account);
    const cache = readLayoutCache(readStoredJson(key));
    this.#first = cache ? Promise.resolve() : new Promise<void>((resolve) => { this.#loaded = resolve; });
    this.#journal = new LayoutJournal(cache);
    this.#cache = createStoredJsonCache(key, () => layoutCacheValue(this.#journal));
    this.#off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.#event(event), () => {
      this.#journal.restart();
    });
  }
  async load(): Promise<CanvasDocument | undefined> {
    await this.#first;
    const document = this.current();
    return this.#journal.initialized || this.#journal.migration || document.views.length ? document : undefined;
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
    if (this.#disposed) return;
    let accepted: boolean;
    try { accepted = this.#journal.accept(event); }
    catch { this.#resync(); return; }
    if (!accepted) {
      // Withdrawals leave the transport healthy. A gap cannot be repaired by
      // ignoring subsequent operations: request a canonical snapshot instead.
      if (event.type === "error") this.#resync();
      else if (Number(event.revision) > this.#journal.canonical.revision) this.#resync(Number(event.revision));
      return;
    }
    if (this.#resyncTarget > 0 && (event.type === "canvas.layout.snapshot" || this.#journal.canonical.revision >= this.#resyncTarget)) {
      clearTimeout(this.#resyncTimer); this.#resyncTimer = undefined;
      this.#resyncTarget = 0; this.#resyncDelay = 250;
    }
    this.#publish(); this.#loaded?.(); this.#loaded = undefined; this.#pump();
  }
  /** One retry timer per account store, including while a replacement snapshot is absent. */
  #resync(revision = Infinity): void {
    if (this.#disposed) return;
    this.#resyncTarget = Math.max(this.#resyncTarget, revision);
    if (this.#resyncTimer !== undefined) return;
    this.#resyncTimer = setTimeout(() => {
      this.#resyncTimer = undefined;
      this.#resyncDelay = Math.min(5000, this.#resyncDelay * 2);
      this.#off.refresh();
      if (this.#resyncTarget > 0) this.#resync(this.#resyncTarget);
    }, this.#resyncDelay);
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
      if (!Number.isSafeInteger(result.revision)) { this.#journal.fail(entry, epoch); this.refused(); this.#resync(); return; }
      // The ordered event usually paints first. Its receipt changes journal metadata only.
      if (this.#journal.acknowledge(entry, Number(result.revision), migration)) this.#publish(); else this.#cache.schedule();
      if (Number(result.revision) > this.#journal.canonical.revision) this.#resync(Number(result.revision));
      this.#pump();
    }, (error: unknown) => {
      if (this.#disposed) return;
      if (error instanceof ActionRefused) {
        if (!this.#journal.refuse(entry, epoch)) return;
        // Roll back this overlay immediately; the subscription remains ready for independent edits.
        this.#publish(); this.refused(true); this.#pump(); return;
      }
      if (!this.#journal.fail(entry, epoch)) return;
      // Keep the identical input for retry after the next snapshot, including its original base revision.
      this.#cache.schedule(); this.refused();
      this.#resync();
    });
    // Bounded pipelining preserves socket order without making each independent edit wait for the previous RTT.
    if (!migration) this.#pump();
  }
  flush(): void { this.#cache.flush(); }
  dispose(): void { this.#cache.dispose(); this.#disposed = true; clearTimeout(this.#resyncTimer); this.#journal.restart(); this.#off(); this.#loaded?.(); }
}
