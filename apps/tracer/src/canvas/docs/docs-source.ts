// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs on the canvas (#302): a Docs view with a window for each page, and a source for the command palette (⌘K).
 *
 * Both come from one file, `/docs/index.json`, written by the docs build (docs-build.ts): every page's title, one-line summary and
 * headings, a few hundred bytes per page. There is no list of pages in the app. A page added to `docs/user/` appears in the Docs
 * view and in ⌘K with no change here.
 *
 * This file is only the doorway, because it ships with the canvas and the canvas has a transfer budget (D188). It is a palette
 * provider that returns the rows once they exist, and a start that runs when the browser is idle after start-up or at the first ⌘K,
 * whichever comes first. The start loads docs-index.on-demand.ts, which fetches the index, offers the Docs view, answers the palette's
 * actions and puts the view back after a scene replaced every view. A server without docs has no index: no Docs view, no docs rows,
 * and the next ⌘K tries again.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";

/** The shape of `index.json` (docs-build.ts `DocsIndexPage`). */
export interface DocsIndexPage { slug: string; title: string; summary: string; headings: { id: string; text: string }[] }

export interface DocsSource { dispose(): void }

export function installDocsSource(core: CoreScreen, cx: Ctx): DocsSource {
  const controller = new AbortController();
  let rows: PaletteEntry[] = [];
  let starting = false;
  const start = (): void => {
    if (starting) return;
    starting = true;
    void onDemand(() => import("./docs-index.on-demand"))
      .then((module) => module.startDocs(core, cx, controller.signal, (made) => { rows = made; }))
      // No docs on this server, or offline: nothing is offered, and the next ⌘K tries again.
      .catch(() => { starting = false; });
  };
  const removeProvider = core.addPaletteProvider(() => { start(); return rows; });
  const idle = (window as { requestIdleCallback?: (callback: () => void, options?: { timeout: number }) => number }).requestIdleCallback;
  const timer = idle ? idle(start, { timeout: 5000 }) : window.setTimeout(start, 2000);
  return {
    dispose() {
      controller.abort();
      removeProvider();
      if (idle) (window as { cancelIdleCallback?: (handle: number) => void }).cancelIdleCallback?.(timer); else window.clearTimeout(timer);
    },
  };
}
