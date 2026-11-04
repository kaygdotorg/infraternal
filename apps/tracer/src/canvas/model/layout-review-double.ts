/** Controlled layout transport for mock-browser reconciliation break-it specs (#243). */
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import type { SubscriptionHandle } from "../../connection";
import { reduce, type Intent } from "./operations";
import type { CanvasDocument } from "./schema";

/** The test double for break-it specs: the store under test, the revisions on both sides, and two ways for a pretend second device to change the layout. */
export interface LayoutReviewDouble {
  store: ServerCanvasStore;
  revision(): { server: number; client: number };
  /** A pretend second device removes the Console view. Returns the new server revision. */
  removeConsole(): number;
  /** A pretend second device makes two edits but announces only the second, so the store sees a gap in revisions. Returns the new server revision. */
  skipRevision(): number;
}

/** A layout transport that keeps the document in memory, plays the server's part, and sends snapshot and operation events to the one subscriber. */
class ReviewTransport implements LayoutTransport {
  readonly isWelcomed = true;
  #listener: ((event: Record<string, unknown>) => void) | undefined;

  constructor(private document: CanvasDocument) {}

  revision(): number { return this.document.revision; }

  subscribe(_filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void): SubscriptionHandle {
    this.#listener = event;
    open?.();
    event({ type: "canvas.layout.snapshot", document: structuredClone(this.document), revision: this.document.revision, initialized: true });
    return Object.assign(() => { this.#listener = undefined; }, { resync: () => {
      if (this.#listener !== event) return;
      open?.();
      event({ type: "canvas.layout.snapshot", document: structuredClone(this.document), revision: this.document.revision, initialized: true });
    } });
  }

  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (action === "canvas.layout.initialize") {
      const document = input.document as CanvasDocument;
      this.document = structuredClone(document);
      this.document.revision++;
      this.#emit({ type: "canvas.layout.snapshot", document: structuredClone(this.document), revision: this.document.revision, initialized: true });
      return Promise.resolve({ revision: this.document.revision });
    }
    if (action !== "canvas.layout.apply" || !input.intent || typeof input.intent !== "object") return Promise.reject(new Error("unexpected layout action"));
    const intent = input.intent as Intent;
    reduce(this.document, intent);
    this.document.revision++;
    const revision = this.document.revision;
    this.#emit({ type: "canvas.layout.operation", revision, op_id: input.op_id, intent, noop: false });
    return Promise.resolve({ revision });
  }

  peer(intent: Intent): number {
    reduce(this.document, intent);
    this.document.revision++;
    this.#emit({ type: "canvas.layout.operation", revision: this.document.revision, op_id: `review-peer-${this.document.revision}`, intent, noop: false });
    return this.document.revision;
  }

  skipRevision(): number {
    const hidden: Intent = { type: "view.update", view_id: "console", name: "Skipped peer edit" };
    const visible: Intent = { type: "view.update", view_id: "console", cell: { x: 9, y: 4 } };
    reduce(this.document, hidden);
    this.document.revision++;
    reduce(this.document, visible);
    this.document.revision++;
    this.#emit({ type: "canvas.layout.operation", revision: this.document.revision, op_id: `review-gap-${this.document.revision}`, intent: visible, noop: false });
    return this.document.revision;
  }

  #emit(event: Record<string, unknown>): void { this.#listener?.(event); }
}

/** The starting document: a Console view with one column, or ten equal columns when `wide`, each holding one window on the given session. */
function initialDocument(host: string, sessionId: string, wide: boolean): CanvasDocument {
  const count = wide ? 10 : 1;
  return {
    format: "infraternal.canvas", version: 1, revision: 1,
    views: [{
      id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 },
      layout: { type: "tiled", columns: Array.from({ length: count }, (_, index) => ({
        id: `review-column-${index}`, weight: 1 / count,
        windows: [{ id: `review-window-${index}`, target: { type: "session", id: sessionId, host } }],
      })) },
    }],
  };
}

/** Makes the double and a `ServerCanvasStore` connected to it. Pass `wide` for the ten-column document. */
export function createLayoutReviewDouble(account: string, host: string, sessionId: string, wide = false): LayoutReviewDouble {
  const transport = new ReviewTransport(initialDocument(host, sessionId, wide));
  const store = new ServerCanvasStore(transport, account, () => undefined);
  return {
    store,
    revision: () => ({ server: transport.revision(), client: store.current().revision }),
    removeConsole: () => transport.peer({ type: "view.remove", view_id: "console" }),
    skipRevision: () => transport.skipRevision(),
  };
}
