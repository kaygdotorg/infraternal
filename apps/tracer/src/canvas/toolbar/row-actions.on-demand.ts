/**
 * What each row of the sidebar tree can do (D309, #242): the per-list half of the shared row menu
 * (packages/ui/src/row-menu.ts owns the gestures and the menu). One list, four kinds of row:
 *
 * - a session (`s:host/id`): Open, Open beside, Rename (in place, the shared field), Copy name, End session… (asks
 *   first, in its row). A left swipe ends it (after the same question), a right swipe opens it beside and the row settles
 *   back in place. End is offered only where the inventory can end a session (`can.end`; the product's cannot yet, #100).
 * - a host (`h:host`): Open (a shell on it), Rename where the Mesh knows the host, Copy name, and the host's removal where
 *   the instance offers it.
 * - a Mesh node (`n-…`): Open (flies to it), Rename, Copy name.
 * - a window (anything else): Open, Copy name, and Close window for a terminal or logs window (the session keeps
 *   running); a left swipe closes it.
 *
 * Every action is also a palette row for the focused row (`rowEntries`), so nothing is reachable only by gesture.
 *
 * It is an on-demand module (D188): the tree loads it the first time the sidebar is shown, with the shared row menu
 * (packages/ui/src/row-menu.ts), the in-row question and the hover pill (row-pill.ts), so none of it is on the first
 * screen's path or in the deferred canvas. It also makes the pill, which asks the same `actions`.
 */
import { branchRowId } from "../../../../../packages/ui/src/branched";
import { writeClipboard, CLIPBOARD } from "../../../../../packages/ui/src/copy-feedback";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { attachRowMenu, type RowAction, type RowMenu } from "../../../../../packages/ui/src/row-menu";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, WinRec } from "../context";
import { coarse } from "../dom";
import { isTerminal } from "../views/body";
import { createRowPill } from "./row-pill";
import { createRowRename } from "./row-rename.on-demand";
import { SESSION_ICON } from "../views/icons";

const OPEN_ICON = '<path d="M5 12h14m-6-6 6 6-6 6"/>';

/** The row element a list item lives in: a leaf's `li`, or a host caption. */
const rowIn = (tree: HTMLElement, target: Element): HTMLElement | undefined => {
  const row = target.closest<HTMLElement>(".bm-row");
  return row && tree.contains(row) && branchRowId(row) ? row : undefined;
};

export interface RowActionsHooks {
  /** Closes the sidebar (a phone: after something opened). */
  closeSidebar(): void;
  /** Opens the rename field on a row of the tree by its id (the menu's Rename); false when the row cannot be renamed. */
  rename(id: string): boolean;
  /** A rename field is open (`true`) or closed (`false`): the tree is not rebuilt under it. */
  editing(open: boolean): void;
}

export function createRowActions(cx: Ctx, tree: HTMLElement, hooks: RowActionsHooks): { menu: RowMenu; openRename(row: HTMLElement): boolean; rowEntries(): PaletteEntry[]; actionsOf(row: HTMLElement): RowAction[]; dispose(): void } {
  const closeSidebar = hooks.closeSidebar;
  const openRename = createRowRename(cx, hooks.editing);
  const inv = cx.adapters.inventory;
  const toast = cx.core.toast;
  const afterOpen = (): void => { if (coarse.matches) closeSidebar(); };
  const copyName = (name: string): RowAction => ({
    id: "copy", label: "Copy name", icon: CLIPBOARD,
    run: () => { void writeClipboard(name).then((ok) => toast.show(ok ? { message: `Copied '${name}'.`, duration: 1800 } : { message: "Couldn't copy the name.", tone: "error" })); },
  });
  const windowOf = (id: string): WinRec | undefined => [...cx.views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === id);

  const actions = (row: HTMLElement): RowAction[] => {
    const id = branchRowId(row);
    if (!id) return [];
    const label = row.querySelector<HTMLElement>(".bm-label") ?? row;
    const name = (label.textContent ?? "").trim();
    if (id.startsWith("s:")) {
      const [host, sid] = id.slice(2).split("/");
      const rec = host && sid ? inv?.get(host, sid) : undefined;
      if (!host || !sid || !rec) return [];
      const out: RowAction[] = [
        { id: "open", label: "Open", icon: OPEN_ICON, run: () => { cx.win.openSession(host, sid); afterOpen(); } },
      ];
      out.push({
        id: "beside", label: "Open beside", icon: SESSION_ICON.beside, swipe: "right", swipeKeeps: true,
        run: () => {
          // A phone shows one window at a time: beside is the same as open there.
          const active = cx.state.activeWin;
          if (!coarse.matches && active && isTerminal(active) && !active.owner.view.team) void cx.win.newWindow(active, "right", false, sid);
          else { cx.win.openSession(host, sid); afterOpen(); }
        },
      });
      if (inv?.can?.rename !== false) out.push({
        id: "rename", label: "Rename", icon: SESSION_ICON.rename,
        run: () => { hooks.rename(id); },
      });
      out.push(copyName(rec.name));
      if (inv?.can?.end !== false) out.push({
        id: "end", label: "End session…", icon: SESSION_ICON.end, danger: true, swipe: "left", swipeLabel: "End",
        // Asked in the row itself (row-confirm.ts): "End session? End · Cancel". The effect is read out, not drawn.
        confirm: {
          title: `End '${rec.name}'?`,
          question: "End session?",
          shortQuestion: "End?",
          effect: rec.running ? `${rec.running} is still running. Ending the session stops it.` : "Nothing is running in it.",
          confirmLabel: "End",
        },
        run: () => { inv?.end(host, sid); const w = cx.sessionUi?.windowFor(host, sid); if (w && !w.owner.view.team) cx.win.close(w); },
      });
      return out;
    }
    if (id.startsWith("h:")) {
      const host = id.slice(2);
      const entry = cx.adapters.sessions.hosts().find((h) => h.name === host);
      const out: RowAction[] = [
        { id: "open", label: "Open shell", icon: OPEN_ICON, run: () => { cx.win.open(host); afterOpen(); } },
      ];
      if (row.hasAttribute("data-renamable")) out.push({ id: "rename", label: "Rename", icon: SESSION_ICON.rename, run: () => { hooks.rename(id); } });
      out.push(copyName(host));
      const removal = cx.adapters.hostRemoval;
      if (entry && entry.id !== "embedded" && removal?.label()) out.push({
        id: "remove", label: `${removal.label()}…`, icon: SESSION_ICON.end, danger: true,
        run: () => removal.remove(entry.id, host, row),
      });
      return out;
    }
    const rec = windowOf(id);
    const out: RowAction[] = [
      { id: "open", label: "Open", icon: OPEN_ICON, run: () => {
        if (!rec) return;
        cx.win.setActive(rec);
        if (rec.model.kind === "node") cx.nav.flyView("mesh"); else cx.nav.focusWindow(rec);
        afterOpen();
      } },
    ];
    if (row.querySelector(".bm-leaf")?.hasAttribute("data-renamable")) out.push({ id: "rename", label: "Rename", icon: SESSION_ICON.rename, run: () => { hooks.rename(id); } });
    out.push(copyName(name));
    if (rec && rec.model.kind !== "node" && rec.model.kind !== "settings") out.push({
      id: "close", label: "Close window", icon: ICONS.close, swipe: "left", swipeLabel: "Close",
      run: () => cx.win.close(rec),
    });
    return out;
  };

  const menu = attachRowMenu(tree, { stage: cx.stage, rowAt: (target) => rowIn(tree, target), actions, anchorOf: (row) => row.querySelector<HTMLElement>(".bm-leaf") ?? row, labelOf: (row) => row.querySelector(".bm-label") });

  /** The focused row's actions, as palette rows: computed when the palette opens, while the row still has focus. */
  const rowEntries = (): PaletteEntry[] => {
    const focused = document.activeElement instanceof Element ? rowIn(tree, document.activeElement) : undefined;
    const id = focused && branchRowId(focused);
    if (!focused || !id) return [];
    const label = (focused.querySelector(".bm-label") ?? focused).textContent?.trim() ?? "";
    return actions(focused).map((a) => ({
      group: "This row", glyph: "›", icon: a.icon,
      label: a.label.replace(/…$/, "") + ` '${label}'`, hint: "this row",
      action: `canvas:row:${a.id}:${encodeURIComponent(id)}`,
    }));
  };
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: string }>).detail;
    const [, kind, verb, raw] = (detail?.action ?? "").split(":");
    if (kind !== "row" || !verb || !raw) return;
    const id = decodeURIComponent(raw);
    const leaf = [...tree.querySelectorAll<HTMLElement>("[data-id]")].find((n) => n.dataset.id === id);
    const row = leaf?.closest<HTMLElement>(".bm-row");
    const action = row && actions(row).find((a) => a.id === verb);
    if (row && action) menu.perform(row, action, "keyboard");
  };
  window.addEventListener("tracer:canvas-action", onAction);
  // The focused row's actions are palette rows, computed when the palette opens.
  const offEntries = cx.core.addPaletteProvider(rowEntries);
  // The hover pill and the F2 / Delete keys (#215): the pointer's and keyboard's shortcuts to the same row actions.
  const offPill = createRowPill(cx, tree, menu, actions, closeSidebar);
  tree.dataset.rows = "ready"; // the row menu, swipes and pill are attached (they load with the sidebar); specs wait for it
  return { menu, openRename, rowEntries, actionsOf: actions, dispose() { window.removeEventListener("tracer:canvas-action", onAction); offEntries(); offPill(); delete tree.dataset.rows; menu.dispose(); } };
}
