/**
 * Keeps the store in step with the canvas: `changed()` is called after every structural change (a window opened,
 * closed, split, moved or resized; a view moved), saves are coalesced to one per 300 ms, and the document carries
 * a revision that grows with every save. Writes happen off the interaction path (a timer), never inside a frame.
 */
import type { Ctx } from "../context";
import { toDocument } from "./document";

export interface DocumentSync {
  changed(): void;
  /** Saves now (the page is being hidden). */
  flush(): void;
  dispose(): void;
}

export function createDocumentSync(cx: Ctx, persisted: (id: string) => boolean = () => true): DocumentSync {
  let timer = 0;
  let revision = 0;
  const save = (): void => {
    timer = 0;
    const models = [...cx.views.values()].filter((c) => persisted(c.view.id)).map((c) => c.view);
    revision += 1;
    void cx.adapters.store.save(toDocument(models, cx.state.metrics, revision));
  };
  return {
    changed() { if (!timer) timer = window.setTimeout(save, 300); },
    flush() { if (timer) { window.clearTimeout(timer); save(); } },
    dispose() { window.clearTimeout(timer); },
  };
}
