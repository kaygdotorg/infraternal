/**
 * Keeps the store in step with the canvas: `changed()` is called after every structural change (a window opened,
 * closed, split, moved or resized; a view moved), edits are captured after the current task, and the document carries
 * a revision that grows with every save. The server store journals semantic edits; no private drawing is persisted in the browser (D312).
 */
import type { Ctx } from "../context";
import type { LayoutEdit } from "./operations";
import type { CanvasDocument } from "./document";
import { documentWindows, toDocument } from "./document";

export interface DocumentSync {
  changed(split?: LayoutEdit): void;
  /** Reset the drawing baseline after a canonical update, without creating local edits. */
  reset(protectedIds?: ReadonlySet<string>, protectedViews?: ReadonlySet<string>): void;
  uncommittedViews(): ReadonlySet<string>;
  /** Local windows not yet represented by a submitted edit. */
  uncommittedWindows(): ReadonlySet<string>;
  /** Saves now (the page is being hidden). */
  flush(): void;
  dispose(): void;
}

/**
 * Creates one canvas document sync. Call `changed()` after structural edits; account appearance changes use the same
 * document adapter. `persisted` selects saved views, leaving the rest local to this tab.
 */
export function createDocumentSync(cx: Ctx, persisted: (id: string) => boolean = () => true): DocumentSync {
  let queued = false;
  let disposed = false;
  let revision = 0;
  let before: CanvasDocument | undefined;
  const splits = new Map<string, LayoutEdit>();
  const document = (): CanvasDocument => toDocument([...cx.views.values()].filter((c) => persisted(c.view.id)).map((c) => c.view), cx.state.metrics, revision, cx.adapters.store.acceptsPendingReferences, cx.adapters.look?.snapshot());
  const save = (): void => {
    queued = false;
    if (disposed) return;
    // A terminal still waiting for its session id is "unresolved": its birth is held until the id arrives. A refused
    // shell's window is not: no id will come, so it stays out of the document instead (#395).
    const unresolved = new Set([...cx.views.values()].flatMap((v) => [...v.wins.values()].filter((w) => w.model.kind === "terminal" && !w.model.sessionId && !w.model.openRefused).map((w) => w.model.id)));
    if (unresolved.size && !cx.adapters.store.acceptsPendingReferences) return;
    revision += 1;
    const next = document();
    void cx.adapters.store.save(next, splits, before, unresolved);
    before = next;
    cx.adapters.inventory?.setLayout?.(cx.adapters.store.current?.() ?? next);
    for (const id of splits.keys()) if (next.views.some((v) => v.layout.type === "tiled" && v.layout.columns.some((c) => c.windows.some((w) => w.id === id)))) splits.delete(id);
  };
  // The person changed the account's look on this page: it is saved with the layout, by the same edits (D322). The adapter waits for a pause, so a slider drag is one save.
  const offLook = cx.adapters.look?.onChange(() => { if (!disposed && !queued) { queued = true; queueMicrotask(() => { if (queued) save(); }); } });
  return {
    changed(split) { if (split) splits.set(split.windowId, split); if (!disposed && !queued) { queued = true; queueMicrotask(() => { if (queued) save(); }); } },
    reset(protectedIds = new Set(), protectedViews = new Set()) {
      before = document();
      // The baseline's look is the one the store holds, not this page's: a page whose look differs from the account's (or an account with none) then saves it.
      const held = cx.adapters.store.current?.().look;
      if (held) before.look = held; else delete before.look;
      before.views = before.views.filter((v) => !protectedViews.has(v.id));
      for (const v of before.views) if (v.layout.type === "tiled") for (const c of v.layout.columns) c.windows = c.windows.filter((w) => !protectedIds.has(w.id));
    },
    uncommittedViews() {
      const saved = new Set(before?.views.map((v) => v.id) ?? []);
      return new Set([...cx.views.keys()].filter((id) => persisted(id) && !saved.has(id)));
    },
    uncommittedWindows() {
      const saved = new Set(before ? documentWindows(before).map((w) => w.id) : []);
      return new Set([...cx.views.values()].filter((v) => persisted(v.view.id) && v.view.layout === "tiled").flatMap((v) => [...v.wins.values()].filter((w) => w.model.kind !== "flow" && w.model.kind !== "node" && w.model.kind !== "app" && w.model.kind !== "screen" && !saved.has(w.model.id)).map((w) => w.model.id)));
    },
    flush() { if (queued) save(); cx.adapters.store.flush?.(); },
    /** After this nothing is written again: sign-out removes the document right after (D245). */
    dispose() { disposed = true; queued = false; offLook?.(); cx.adapters.store.dispose?.(); },
  };
}
