/**
 * Keeps the store in step with the canvas: `changed()` is called after every structural change (a window opened,
 * closed, split, moved or resized; a view moved), edits are captured after the current task, and the document carries
 * a revision that grows with every save. The server store journals semantic edits; only its drawing cache serialization is delayed.
 */
import type { Ctx } from "../context";
import type { SplitEdit } from "./operations";
import type { CanvasDocument } from "./document";
import { toDocument } from "./document";

export interface DocumentSync {
  changed(split?: SplitEdit): void;
  /** Reset the drawing baseline after a canonical update, without creating local edits. */
  reset(): void;
  /** Saves now (the page is being hidden). */
  flush(): void;
  dispose(): void;
}

export function createDocumentSync(cx: Ctx, persisted: (id: string) => boolean = () => true): DocumentSync {
  let timer = 0;
  let disposed = false;
  let revision = 0;
  let before: CanvasDocument | undefined;
  const splits = new Map<string, SplitEdit>();
  const document = (): CanvasDocument => toDocument([...cx.views.values()].filter((c) => persisted(c.view.id)).map((c) => c.view), cx.state.metrics, revision);
  const save = (): void => {
    timer = 0;
    if (disposed) return;
    // A split's reference arrives asynchronously. Persist it once, after the new shell has an ID,
    // rather than sending its intermediate resized anchor before the split itself.
    if ([...cx.views.values()].some((v) => persisted(v.view.id) && [...v.wins.values()].some((w) => w.model.kind === "terminal" && !w.model.sessionId))) return;
    revision += 1;
    const next = document();
    void cx.adapters.store.save(next, splits, before);
    before = next;
    cx.adapters.inventory?.setLayout?.(next);
    for (const id of splits.keys()) if (next.views.some((v) => v.layout.type === "tiled" && v.layout.columns.some((c) => c.windows.some((w) => w.id === id)))) splits.delete(id);
  };
  return {
    changed(split) { if (split) splits.set(split.windowId, split); if (!disposed && !timer) timer = window.setTimeout(save, 0); },
    reset() { before = document(); },
    flush() { if (timer) { window.clearTimeout(timer); save(); } cx.adapters.store.flush?.(); },
    /** After this nothing is written again: sign-out removes the document right after (D245). */
    dispose() { disposed = true; window.clearTimeout(timer); timer = 0; cx.adapters.store.dispose?.(); },
  };
}
