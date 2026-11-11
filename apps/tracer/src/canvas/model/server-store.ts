/** Per-tab canvas intents and same-ID snapshot recovery; the server is the only saved copy (D312). A refused whole-look CAS requests a fresh snapshot before publishing canonical state. */
import { canvasKey, readStoredJson } from "../../account-storage";
import { parseDocument, type CanvasDocument, type DocLook } from "./schema";
import type { LayoutEdit } from "./operations";
import { ActionRefused, type SubscriptionHandle } from "../../connection";
import { registerAccountWork } from "../../account-lifetime";
import { randomUuid } from "../../identifiers";
import { LayoutJournal, LayoutQueueFull } from "./journal";
import type { CanvasStore } from "./store";

export interface LayoutTransport {
  readonly isWelcomed?: boolean;
  readonly sessionIncarnation?: string | undefined;
  readonly roundTripMs?: number | undefined;
  readonly recoveryRoundTrips?: 1 | 4;
  onRoundTrip?(listener: (ms: number | undefined) => void): () => void;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  subscribe(filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): SubscriptionHandle;
}
/**
 * What a session revocation did to this tab's queued layout work. Only a server receipt proves an
 * edit committed (D312), so work is split by what the tab can actually know:
 * - `unsent`: at least one edit never left the tab; clearing the queue dropped it.
 * - `unconfirmed`: everything left the tab, but some has no receipt; it may or may not have committed.
 * - `none`: nothing queued, or every queued edit has a receipt and reappears on the next sign-in.
 */
export type RevokedWork = "none" | "unconfirmed" | "unsent";

/** Keeps the account document current, journals optimistic edits, and recovers server-confirmed state after gaps or refusals. */
export class ServerCanvasStore implements CanvasStore {
  readonly acceptsPendingReferences = true;
  readonly #journal: LayoutJournal;
  readonly #listeners = new Set<() => void>();
  readonly #status = new Set<() => void>();
  #disposed = false;
  #paused = false;
  readonly #offAccount: () => void;
  #resyncing = false;
  #waiting = false;
  #off: SubscriptionHandle | undefined;
  readonly #offRtt: (() => void) | undefined;
  #retry: ReturnType<typeof setTimeout> | undefined;
  #watchdog: ReturnType<typeof setTimeout> | undefined;
  #notice: ReturnType<typeof setTimeout> | undefined;
  #delay = 250;
  #target = 0;
  #pendingSince: number | undefined;
  #notified = false;
  #rtt: number | undefined;
  #loaded: (() => void) | undefined;
  readonly #first: Promise<void>;
  readonly #legacyKey: string;
  #imported = false;
  #incarnation: string | undefined;
  #revoked = false;

  /** Opens the account subscription and starts its bounded local journal.
   * @param transport The authenticated connection for document requests and snapshots.
   * @param account The account whose shared canvas document this tab edits.
   * @param refused The existing callback for layout-save notices.
   * @param onSessionRevoked The callback that ends this canvas when its account lifetime changes.
   * @param onLookRefused Runs only when the server definitively refuses a whole-look compare-and-set.
   */
  constructor(
    private readonly transport: LayoutTransport,
    account: string,
    private readonly refused: (definitive?: boolean, delayed?: boolean, capacity?: boolean) => void = () => {},
    private readonly onSessionRevoked: (work: RevokedWork) => void = () => {},
    private readonly onLookRefused: (look: DocLook) => void = () => {},
  ) {
    this.#offAccount = registerAccountWork(account, { pause: (value) => { this.#paused = value; if (!value) this.#pump(); }, dispose: () => this.dispose() });
    this.#incarnation = transport.sessionIncarnation;
    this.#legacyKey = canvasKey(account);
    // Read only the shipped v1 import. Unconfirmed/unreadable journals remain untouched for explicit export/discard.
    const legacy = parseDocument(readStoredJson(this.#legacyKey));
    this.#journal = new LayoutJournal(legacy ? { canonical: { format: "infraternal.canvas", version: 1, revision: 0, views: [] }, pending: [], unresolved: new Set(), migration: { op_id: randomUuid(), document: legacy } } : undefined);
    this.#first = new Promise<void>((resolve) => { this.#loaded = resolve; });
    this.#rtt = transport.roundTripMs;
    this.#offRtt = transport.onRoundTrip?.((ms) => { this.#rtt = ms; this.#pendingChanged(); });
    this.#off = transport.subscribe({ topic: "canvas.layout" }, (event) => this.#event(event), () => {
      if (this.#disposed) return;
      const incarnation = this.transport.sessionIncarnation;
      if (incarnation !== this.#incarnation && (this.#incarnation !== undefined || this.pending)) {
        const work = this.#revokedWork();
        this.#journal.clear(); this.#revoked = true;
        this.#publish(); this.#pendingChanged();
        // A changed lifetime has no authority to keep drawing: the caller ends the old account screen.
        this.onSessionRevoked(work);
        return;
      } else this.#incarnation = incarnation;
      this.#journal.restart(); this.#resyncing = true; this.#waiting = true;
      clearTimeout(this.#retry); this.#retry = undefined;
      this.#watch();
    });
  }
  #revokedWork(): RevokedWork {
    const { pending, migration } = this.#journal;
    if (pending.some((p) => !p.sent)) return "unsent";
    // A migration keeps its legacy source on disk until confirmed, so it is never dropped outright.
    if (pending.some((p) => p.revision === undefined) || (migration && migration.revision === undefined)) return "unconfirmed";
    return "none";
  }
  get pending(): boolean { return this.#journal.pending.length > 0 || this.#journal.migration !== undefined; }
  onPending(listener: () => void): () => void { if (!this.#disposed) this.#status.add(listener); return () => { this.#status.delete(listener); }; }
  async load(): Promise<CanvasDocument | undefined> {
    await this.#first;
    if (this.#disposed) return undefined;
    const document = this.current();
    return this.#journal.initialized || this.#journal.migration || document.views.length ? document : undefined;
  }
  unresolvedWindow(id: string): boolean { return this.#journal.unresolved.has(id); }
  /** Local acceptance only: drawing and typing never await confirmation. */
  async save(doc: CanvasDocument, hints?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved: ReadonlySet<string> = new Set()): Promise<void> {
    if (this.#disposed || this.#revoked) return;
    // Input is frozen by the screen during logout; admitted asynchronous references may
    // still finish in RAM. The pump stays paused until revocation fails or disposal clears it.
    try { if (this.#journal.capture(doc, hints, before, unresolved)) this.#publish(); }
    catch (error) { if (!(error instanceof LayoutQueueFull)) throw error; this.refused(false, false, true); this.#publish(); }
    this.#pendingChanged(); this.#pump();
  }
  current(): CanvasDocument { return this.#journal.current(); }
  subscribe(listener: () => void): () => void { if (!this.#disposed) this.#listeners.add(listener); return () => { this.#listeners.delete(listener); }; }
  #event(event: Record<string, unknown>): void {
    if (this.#disposed || this.#revoked) return;
    if (event.type === "error") {
      const outstanding = this.#waiting;
      this.#waiting = false; clearTimeout(this.#watchdog); this.#watchdog = undefined;
      if (outstanding) this.#scheduleRetry(); else this.#recover();
      return;
    }
    if (event.type === "canvas.layout.operation" && this.#resyncing) return;
    let accepted = false;
    try { accepted = this.#journal.accept(event); } catch { /* malformed history needs a fresh snapshot */ }
    if (!accepted) {
      if (Number(event.revision) > this.#journal.canonical.revision) this.#recover(Number(event.revision));
      return;
    }
    if (event.type === "canvas.layout.snapshot") {
      this.#waiting = this.#resyncing = false;
      clearTimeout(this.#watchdog); this.#watchdog = undefined;
    }
    if (event.type === "canvas.layout.snapshot" || this.#journal.canonical.revision >= this.#target) {
      clearTimeout(this.#retry); this.#retry = undefined; this.#target = 0; this.#delay = 250;
    }
    this.#retireImport();
    this.#publish(); this.#pendingChanged(); this.#loaded?.(); this.#loaded = undefined; this.#pump();
  }
  /** Both receipt/snapshot orderings must reach canonical before retiring a confirmed import. */
  #retireImport(): void {
    if (!this.#imported || this.#journal.migration) return;
    try { localStorage.removeItem(this.#legacyKey); this.#imported = false; }
    catch { this.refused(false, true); }
  }
  /** First gap/withdrawal requests immediately. One outstanding snapshot owns its bounded watchdog. */
  #recover(revision = Infinity): void {
    if (this.#disposed) return;
    this.#target = Math.max(this.#target, revision); this.#resyncing = true;
    if (this.#waiting || this.#retry !== undefined || this.transport.isWelcomed === false) return;
    this.#waiting = true;
    this.#off?.resync(); this.#watch();
  }
  #watch(): void {
    clearTimeout(this.#watchdog);
    if (!this.#waiting || this.#disposed || this.transport.isWelcomed === false) return;
    this.#watchdog = setTimeout(() => {
      this.#watchdog = undefined; this.#waiting = false; this.#scheduleRetry();
    }, Math.max(30_000, (this.#rtt ?? 1000) * 4 + 50));
  }
  #scheduleRetry(): void {
    if (this.#disposed || this.#retry !== undefined || this.transport.isWelcomed === false) return;
    const delay = this.#delay * (1 + Math.random() / 2); this.#delay = Math.min(5000, this.#delay * 2);
    this.#retry = setTimeout(() => { this.#retry = undefined; this.#recover(this.#target); }, delay);
  }
  #pendingChanged(): void {
    for (const listener of this.#status) listener();
    clearTimeout(this.#notice); this.#notice = undefined;
    if (!this.pending) { this.#pendingSince = undefined; this.#notified = false; return; }
    this.#pendingSince ??= performance.now();
    if (this.#notified || this.#disposed) return;
    const budget = (this.#rtt ?? 1000) * (this.transport.recoveryRoundTrips ?? 4) + 50;
    this.#notice = setTimeout(() => { this.#notice = undefined; if (!this.#disposed && this.pending) { this.#notified = true; this.refused(false, true); } }, Math.max(0, budget - (performance.now() - this.#pendingSince)));
  }
  #publish(): void { for (const listener of this.#listeners) listener(); }
  /** Sends the next journaled intent when the connection is ready; a definitive refusal of a whole-look edit also requests a fresh snapshot. */
  #pump(): void {
    if (this.#disposed || this.#revoked || this.#paused || this.#resyncing || this.transport.isWelcomed === false) return;
    const entry = this.#journal.next(); if (!entry) return;
    const migration = "document" in entry, epoch = this.#journal.epoch;
    const binding = this.#incarnation === undefined ? {} : { session_incarnation: this.#incarnation };
    const input = "document" in entry ? { ...binding, op_id: entry.op_id, document: entry.document } : { ...binding, op_id: entry.op_id, base_revision: entry.base_revision, intent: entry.intent };
    void this.transport.call(migration ? "canvas.layout.initialize" : "canvas.layout.apply", input).then((result) => {
      if (this.#disposed || !this.#journal.release(entry, epoch)) return;
      if (!Number.isSafeInteger(result.revision) || Number(result.revision) < 0) { this.#journal.fail(entry, epoch); this.#recover(); return; }
      if (migration) this.#imported = true;
      if (this.#journal.acknowledge(entry, Number(result.revision), migration)) this.#publish();
      this.#retireImport(); this.#pendingChanged();
      // A receipt ahead of canonical can still be followed by its ordinary ordered event.
      if (Number(result.revision) > this.#journal.canonical.revision) {
        this.#target = Math.max(this.#target, Number(result.revision));
        if (this.#retry === undefined) this.#scheduleRetry();
      }
      this.#pump();
    }, (error: unknown) => {
      if (this.#disposed) return;
      if (error instanceof ActionRefused) {
        if (!this.#journal.refuse(entry, epoch)) return;
        const refusedLook = "intent" in entry && entry.intent.type === "look.set" ? entry.intent.look : undefined;
        if (refusedLook) {
          // A stale whole-look edit has no safe local rollback until the current account document arrives.
          this.onLookRefused(refusedLook);
          this.#recover();
        } else this.#publish();
        this.#pendingChanged(); this.refused(true); this.#pump(); return;
      }
      if (!this.#journal.fail(entry, epoch)) return;
      this.#pendingChanged(); this.#recover();
    });
    if (!migration) this.#pump();
  }
  /** Kept for the canvas adapter: there is no persistence or full-history serialization. */
  flush(): void {}
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    clearTimeout(this.#retry); clearTimeout(this.#watchdog); clearTimeout(this.#notice);
    this.#offAccount(); this.#offRtt?.(); this.#off?.(); this.#listeners.clear(); this.#status.clear();
    this.#journal.clear();
    this.#loaded?.(); this.#loaded = undefined;
  }
}
