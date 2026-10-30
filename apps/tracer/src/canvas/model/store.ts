/**
 * The canvas store adapter: where the canvas document lives (D178, D180, D183).
 *
 * Product uses ServerCanvasStore: revisions and semantic intents over the existing connection.
 * LocalCanvasStore remains for isolated previews. Production never writes private layout data to browser storage (D312).
 * Cameras and focus belong to each device and never enter this interface.
 */
import { parseDocument, type CanvasDocument } from "./schema";
import type { LayoutEdit } from "./operations";
import { canvasKey } from "../../account-storage";

export interface CanvasStore {
  readonly acceptsPendingReferences?: boolean;
  readonly pending?: boolean;
  onPending?(listener: () => void): () => void;
  load(): Promise<CanvasDocument | undefined>;
  save(doc: CanvasDocument, splits?: ReadonlyMap<string, LayoutEdit>, before?: CanvasDocument, unresolved?: ReadonlySet<string>): Promise<void>;
  current?(): CanvasDocument;
  unresolvedWindow?(id: string): boolean;
  flush?(): void;
  dispose?(): void;
  /** Read the latest projection after asynchronous work instead of retaining an obsolete event snapshot. */
  subscribe(listener: () => void): () => void;
}

export class LocalCanvasStore implements CanvasStore {
  private readonly key: string;
  private document: CanvasDocument | undefined;
  constructor(account: string) { this.key = canvasKey(account); }
  async load(): Promise<CanvasDocument | undefined> {
    if (this.document) return this.document;
    try {
      const raw = localStorage.getItem(this.key);
      return raw ? parseDocument(JSON.parse(raw)) : undefined;
    } catch { return undefined; }
  }
  async save(doc: CanvasDocument): Promise<void> {
    this.document = structuredClone(doc);
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
