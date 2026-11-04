/**
 * The action pill on a sidebar row (#215): small icon buttons at the row's right end that show while the pointer is on
 * the row or the row has keyboard focus, so Info, Rename and Remove are one glance away without a menu. The pill is the
 * pointer's shortcut to what the row menu (row-actions.on-demand.ts) already offers; it asks the same `actions` the menu does, so
 * a row never shows a button for something it cannot do (a host the Mesh does not know has no Rename; a session cannot
 * be ended until the inventory can, #100).
 *
 * - Hover only (`hover: hover` and a fine pointer). The pill never covers the row's marks and notes (their tooltips are #259's). A phone has the long-press menu and the swipes, which are the same
 *   actions; a pill would only crowd a 44 px row.
 * - Made when the pointer or the keyboard enters a row, so a list of dozens of rows carries no hidden buttons
 *   at rest. It is the shared window action pill (`.ui-window-actions`, `.ui-window-action`) and the shared warm tooltips.
 * - Info opens the details of the window that shows the host or session; a row without a window has no Info.
 * - Keys on a focused row: F2 renames, Delete (Backspace on a Mac keyboard) runs the row's one destructive action
 *   (End session, Remove host), which asks in its row or in the host-removal flow, never at once.
 */
import { ICON_INFO } from "../../../../../packages/ui/src/icons";
import type { RowAction, RowMenu } from "../../../../../packages/ui/src/row-menu";
import type { Ctx, WinRec } from "../context";
import { el } from "../dom";
import { SESSION_ICON } from "../views/icons";

/** The three actions of the row pill. */
type Act = "info" | "rename" | "remove";
/** The tooltip of each action. */
const TIP: Record<Act, string> = { info: "Info", rename: "Rename", remove: "Remove" };
/** Icon paths (a bin) for Remove. */
const BIN = '<path d="M5 7h14M10 7V4.5h4V7M7 7l.8 12.5h8.4L17 7M10.5 11v5M13.5 11v5"/>';
/** The icon paths of each action. */
const ICON: Record<Act, string> = { info: ICON_INFO, rename: SESSION_ICON.rename, remove: BIN };

/** The row (a host caption or a session's `li`) a node is in, with the id the tree wrote on it. */
const rowOf = (tree: HTMLElement, node: Element | null): { row: HTMLElement; id: string } | undefined => {
  const row = node?.closest<HTMLElement>("li.bm-subhead[data-id], li.bm-row");
  if (!row || !tree.contains(row)) return undefined;
  const id = row.dataset.id ?? row.querySelector<HTMLElement>(".bm-leaf")?.dataset.id;
  return id && (id.startsWith("h:") || id.startsWith("s:")) ? { row, id } : undefined;
};

/**
 * Wires the hover action pill on the rows of the sidebar `tree`. `actionsOf` gives the row's menu actions, which the pill reuses. Returns the
 * function that removes the listeners; `closeSidebar` is called when an action needs the sidebar out of the way.
 */
export function createRowPill(cx: Ctx, tree: HTMLElement, menu: RowMenu, actionsOf: (row: HTMLElement) => RowAction[], closeSidebar: () => void): () => void {
  const abort = new AbortController();
  const { signal } = abort;
  const windowOf = (id: string): WinRec | undefined => {
    const wins = [...cx.views.values()].flatMap((c) => [...c.wins.values()]);
    if (id.startsWith("s:")) { const [host, sid] = id.slice(2).split("/"); return host && sid ? cx.sessionUi?.windowFor(host, sid) : undefined; }
    return wins.find((w) => w.model.kind === "terminal" && `h:${w.model.host}` === id);
  };
  /** Which pill buttons this row has right now. */
  const available = (row: HTMLElement, id: string): Array<{ act: Act; action?: RowAction }> => {
    const actions = actionsOf(row);
    const out: Array<{ act: Act; action?: RowAction }> = [];
    if (windowOf(id) && cx.details) out.push({ act: "info" });
    const rename = actions.find((a) => a.id === "rename");
    if (rename) out.push({ act: "rename", action: rename });
    const remove = actions.find((a) => a.danger);
    if (remove) out.push({ act: "remove", action: remove });
    return out;
  };
  const build = (row: HTMLElement, id: string): void => {
    row.querySelector(".cl-ha")?.remove();
    const acts = available(row, id);
    if (!acts.length) return;
    const name = (row.querySelector(".bm-label") ?? row).textContent?.trim() ?? "";
    const wrap = el("span", "cl-ha");
    const group = el("span", "ui-window-actions");
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", `Actions for ${name}`);
    for (const { act, action } of acts) {
      const button = el("button", "ui-window-action");
      button.type = "button";
      button.dataset.act = act;
      button.dataset.tip = action ? action.label.replace(/…$/, "") : TIP[act];
      button.setAttribute("aria-label", `${button.dataset.tip} ${name}`);
      button.tabIndex = -1; // the row owns the keyboard (F2, Delete, the menu key); the pill is for the pointer
      // Ending a session is the stop square (as in the row menu); removing a host is the bin.
      button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${act === "remove" && action?.id === "end" ? SESSION_ICON.end : ICON[act]}</svg>`;
      group.append(button);
    }
    wrap.append(group);
    row.append(wrap);
    // The row's quiet notes (the new-output dot, ✓ 0, the detached icon) keep their place and their tooltips: the pill sits to
    // the left of them and covers the end of the name instead (a name that long is already cut by an ellipsis).
    const edge = row.getBoundingClientRect().right;
    let left = edge;
    for (const note of row.querySelectorAll<HTMLElement>(".ui-mark, .bm-meta")) {
      const r = note.getBoundingClientRect();
      if (r.width >= 1 && r.height >= 1) left = Math.min(left, r.left);
    }
    if (left < edge) wrap.style.right = `${Math.round(edge - left + 4)}px`;
  };
  /** Made when the pointer or the focus enters a row (not on every move inside it), so it always reflects what the row can do now. */
  const reach = (event: Event): void => {
    const hit = rowOf(tree, event.target as Element);
    const from = (event as PointerEvent | FocusEvent).relatedTarget;
    // Pressing a pill button focuses it: remaking the pill then would remove the button between the press and the release.
    if (!hit || (event.target as Element).closest(".cl-ha") || (from instanceof Node && hit.row.contains(from))) return;
    build(hit.row, hit.id);
  };
  tree.addEventListener("pointerover", (e) => { if (e.pointerType === "mouse") reach(e); }, { signal, passive: true });
  tree.addEventListener("focusin", reach, { signal });

  tree.addEventListener("click", (event) => {
    const button = (event.target as Element).closest<HTMLElement>(".cl-ha [data-act]");
    const hit = rowOf(tree, button);
    if (!button || !hit) return;
    event.stopPropagation();
    event.preventDefault();
    const act = button.dataset.act as Act;
    const found = available(hit.row, hit.id).find((a) => a.act === act);
    if (act === "info") {
      const rec = windowOf(hit.id);
      if (rec) { cx.win.setActive(rec); cx.nav.focusWindow(rec); cx.details?.toggle(rec, "pointer"); closeSidebar(); }
    } else if (found?.action) menu.perform(hit.row, found.action, event instanceof MouseEvent && event.detail === 0 ? "keyboard" : "pointer");
  }, { signal, capture: true });

  tree.addEventListener("keydown", (event) => {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey || (event.target as Element).closest("input")) return;
    const hit = rowOf(tree, event.target as Element);
    if (!hit) return;
    const actions = actionsOf(hit.row);
    const action = event.key === "F2" ? actions.find((a) => a.id === "rename") : event.key === "Delete" || event.key === "Backspace" ? actions.find((a) => a.danger) : undefined;
    if (!action) return;
    event.preventDefault();
    event.stopPropagation();
    menu.perform(hit.row, action, "keyboard");
  }, { signal });

  return () => { abort.abort(); };
}
