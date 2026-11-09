// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the "?" button, its shortcut and its ⌘K row do (issue #304): open a preview of the docs for this window, anchored to the "?" (a bottom sheet
 * on a phone). The preview shows the most helpful few lines; its expand icon opens the whole page as a window in the Docs cluster. One function, so the
 * three ways in cannot differ. Pressing the button again closes the preview; a window with no page yet says so in the preview itself.
 */
import type { DocsPreviewContent } from "../../../../../packages/ui/src/docs-preview.on-demand";
import { onDemand } from "../../on-demand";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import type { Ctx, WinRec } from "../context";
import { coarse } from "../dom";

let current: { rec: WinRec; close(source: "pointer" | "keyboard"): void } | undefined;

/** The button that opened it, or what stands in when the action group has folded into its "…" menu. */
function anchorOf(rec: WinRec): HTMLElement {
  const header = rec.card.header;
  const wanted = [header.querySelector<HTMLElement>('.ui-window-action[data-action="docs"]'), header.querySelector<HTMLElement>(".ui-window-more"), rec.card.pill];
  return wanted.find((n): n is HTMLElement => !!n && n.getBoundingClientRect().width > 0) ?? rec.card.pill;
}

/** Opens (or closes) the docs preview for `rec`. `source` only places focus and defaults to the real last input; motion is read by the popover itself. */
export function openWindowDocs(cx: Ctx, rec: WinRec, source: "pointer" | "keyboard" = triggeredByKeyboard() ? "keyboard" : "pointer"): void {
  const adapter = cx.adapters.docs;
  const entry = adapter?.for(rec.model);
  if (!adapter || !entry) return;
  if (current?.rec === rec) { current.close(source); return; }
  current?.close("keyboard");
  const title = rec.model.host;
  const link = entry.link;
  const content: DocsPreviewContent | Promise<DocsPreviewContent> = link
    ? adapter.preview(link).then((found) => found ?? { title, bullets: [], empty: "That page is not available right now." })
    : { title, bullets: [], empty: "There is no page about this yet." };
  // The preview's code (the popover, the sheet and their styles) loads when a "?" is first pressed (D188); until it has, the button's second press only closes nothing.
  let closeNow: ((source: "pointer" | "keyboard") => void) | undefined, closedEarly: "pointer" | "keyboard" | undefined;
  const mark = { rec, close: (s: "pointer" | "keyboard") => { if (closeNow) closeNow(s); else closedEarly = s; } };
  current = mark;
  void onDemand(() => import("../../../../../packages/ui/src/docs-preview.on-demand")).then((m) => {
    if (closedEarly) { if (current === mark) current = undefined; return; }
    const handle = m.openDocsPreview({
      stage: cx.stage, anchor: anchorOf(rec), label: `About ${title}`, content, touch: coarse.matches, source,
      ...(link ? { onExpand: () => { void adapter.open(link).then((found) => { if (!found) cx.core.toast.show({ message: "That page is not available right now." }); }); } } : {}),
      onClosed: () => { if (current === mark) current = undefined; },
    });
    closeNow = handle.close;
  });
}
