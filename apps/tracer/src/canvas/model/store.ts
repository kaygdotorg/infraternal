/**
 * The canvas store adapter: where the canvas document lives (D178, D180, D183).
 *
 * Today: the browser's local storage, per account (`LocalCanvasStore`). Tomorrow: the server, which keeps the
 * document in SQLite as an operation log plus snapshots and syncs it over the same WebSocket (#98). The canvas
 * only ever talks to this interface, so that change replaces one class.
 *
 * The contract:
 * - `load` returns the last saved document, or nothing (first run, cleared storage, damaged data).
 * - `save` stores the whole document; the server implementation will turn successive saves into operations that
 *   carry their base revision (the later edit of a window wins, a close beats a move or a resize).
 * - `subscribe` delivers changes that came from elsewhere (another device); the local store never calls it.
 * - Each device keeps only its own camera; the camera is not part of the document.
 * Storage may be unavailable (private mode, blocked): every method then behaves as an empty store.
 */
import { parseDocument, type CanvasDocument } from "./document";

export interface CanvasStore {
  load(): Promise<CanvasDocument | undefined>;
  save(doc: CanvasDocument): Promise<void>;
  subscribe(listener: (doc: CanvasDocument) => void): () => void;
}

export class LocalCanvasStore implements CanvasStore {
  private readonly key: string;
  constructor(account: string) { this.key = `infraternal.canvas.${account}`; }
  async load(): Promise<CanvasDocument | undefined> {
    try {
      const raw = localStorage.getItem(this.key);
      return raw ? parseDocument(JSON.parse(raw)) : undefined;
    } catch { return undefined; }
  }
  async save(doc: CanvasDocument): Promise<void> {
    try { localStorage.setItem(this.key, JSON.stringify(doc)); } catch { /* storage unavailable: the layout lives for this tab only */ }
  }
  subscribe(): () => void { return () => undefined; }
}

/** A store that keeps nothing (mockups, tests). */
export class MemoryCanvasStore implements CanvasStore {
  private doc: CanvasDocument | undefined;
  async load(): Promise<CanvasDocument | undefined> { return this.doc; }
  async save(doc: CanvasDocument): Promise<void> { this.doc = doc; }
  subscribe(): () => void { return () => undefined; }
}
