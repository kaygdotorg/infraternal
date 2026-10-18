/**
 * The canvas store adapter: where the canvas document lives (D178, D180, D183).
 *
 * Product uses ServerCanvasStore: revisions and semantic intents over the existing connection.
 * LocalCanvasStore remains for isolated previews. Local storage is only a drawing cache in production.
 * Cameras and focus belong to each device and never enter this interface.
 */
import { parseDocument, type CanvasDocument } from "./document";
import type { LayoutEdit } from "./operations.on-demand";
import { canvasKey } from "../../account-storage";

export interface CanvasStore {
  load(): Promise<CanvasDocument | undefined>;
  save(doc: CanvasDocument, splits?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument): Promise<void>;
  flush?(): void;
  dispose?(): void;
  subscribe(listener: (doc: CanvasDocument) => void): () => void;
}

export class LocalCanvasStore implements CanvasStore {
  private readonly key: string;
  constructor(account: string) { this.key = canvasKey(account); }
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
