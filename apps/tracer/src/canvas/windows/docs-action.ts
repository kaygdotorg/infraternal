// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the "?" button, its shortcut and its ⌘K row do (issue #304): open the docs heading that explains a window as a window
 * in the Docs cluster, or say in plain words that there is no page about it yet. One function, so the three ways in cannot differ.
 */
import type { Ctx, WinRec } from "../context";

export function openWindowDocs(cx: Ctx, rec: WinRec): void {
  const adapter = cx.adapters.docs;
  const entry = adapter?.for(rec.model);
  if (!adapter || !entry) return;
  if (!entry.link) { cx.core.toast.show({ message: "There is no page about this yet." }); return; }
  void adapter.open(entry.link).then((found) => { if (!found) cx.core.toast.show({ message: "That page is not available right now." }); });
}
