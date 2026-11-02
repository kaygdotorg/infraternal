// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Renaming a row of the sidebar tree in place (#215, #259): the field, where it goes, and where the new name is saved. An
 * on-demand module (D188): the tree only knows which rows may be renamed and what gesture starts it; this loads with the
 * sidebar's row actions, which hand it to the tree.
 *
 * - The field is the shared inline-rename field, laid over the row's name (never inside its button).
 * - A session (`s:host/id`) is saved through the inventory; its name and pin travel through the account's canvas layout
 *   stream (#293). A host (`h:host`) or a Mesh node (`n-…`) is saved through the Mesh API (`mesh.node.rename`, #259), which says
 *   why in the shared toast when the server refuses.
 * - The tree is not rebuilt while a field is open (`editing`); it is, once the person is done.
 */
import { beginInlineRename, placeOverName, type InlineRename } from "../../../../../packages/ui/src/inline-rename.on-demand";
import type { Ctx } from "../context";
import { renameHost } from "../mesh/rename.on-demand";

export function renameRow(cx: Ctx, id: string, name: string): Promise<void> {
  if (id.startsWith("s:")) {
    const [host, sid] = id.slice(2).split("/");
    if (host && sid) cx.adapters.inventory?.rename(host, sid, name);
    return Promise.resolve();
  }
  return cx.mesh ? renameHost(cx, id.replace(/^(n-|h:)/, ""), name) : Promise.reject(new Error("Renaming is not available."));
}

/** Returns what the tree's `openRename` calls. `editing` tells the tree a field is open (`true`) or closed (`false`). */
export function createRowRename(cx: Ctx, editing: (open: boolean) => void): (row: HTMLElement) => boolean {
  let renaming: InlineRename | undefined;
  return (row) => {
    const label = row.querySelector<HTMLElement>(".bm-label");
    const id = row.dataset.id;
    if (!label || !id || renaming) return false;
    const container = row.matches(".bm-leaf") ? row.parentElement! : row;
    const was = label.textContent ?? "";
    let restore = (): void => undefined;
    editing(true);
    renaming = beginInlineRename({
      value: was,
      label: row.dataset.renameLabel ?? "Host name",
      place: (input) => { restore = placeOverName(label, container, input); },
      commit: (value) => {
        const next = value.trim();
        if (!next || next === was) return;
        label.textContent = next;
        row.dataset.pending = "";
        row.setAttribute("aria-busy", "true");
        const settle = (): void => { delete row.dataset.pending; row.removeAttribute("aria-busy"); };
        renameRow(cx, id, next).then(settle, () => { label.textContent = was; settle(); });
      },
      close: () => { restore(); renaming = undefined; editing(false); },
    });
    return true;
  };
}
