/**
 * The anchored actions menu (TASTE: title first). A narrow window's ⋯ opens its actions here, and the sidebar's profile
 * pill opens its menu (Settings, Sign out) here too: one menu, one material, one set of rows. Loaded when a menu is
 * first opened (D188): a window that is not narrow never needs it, so the card that every window draws does not carry
 * the popover.
 *
 * Keyboard: opened by keyboard, focus lands on the first row; ↑ and ↓ walk the rows, Home and End jump, Escape closes
 * and returns to the anchor. A press on a row closes the menu first, then runs the action.
 */
import { openAnchoredPopover, type AnchoredPopover, type AnchoredPopoverOptions, type PopoverSource } from "./anchored-popover";

/** One row of a window menu: its icon and label, what pressing it does, and how it is drawn. */
export interface WindowMenuItem {
  id: string; label: string; icon: string; run(event: MouseEvent): void;
  /** A destructive row: drawn in the danger colour, after a hairline that sets it apart from the rows above. */
  danger?: boolean;
  /** The menu stays open when the row is pressed, so the row can answer in place; the action closes it itself. */
  keepOpen?: boolean;
}

/** How a window menu is named, sized and placed. */
export interface WindowMenuOptions {
  /** The dialog's accessible name. Default "Window actions". */
  label?: string;
  side?: "below" | "above";
  align?: "start" | "end";
  /** Size to the rows instead of the full width (a short menu). */
  hug?: boolean;
  maxWidth?: number;
  /** Opens at a pointer position (a right-click) instead of under the anchor; see anchored-popover.ts. */
  at?: { x: number; y: number };
  /** With `at`: centre the menu on the point's x instead of starting at it (a callout over a selection). */
  atAlign?: "start" | "centre";
  /** With `at`: keep the menu inside this client box (a window's content area); see anchored-popover.ts. */
  bounds?: AnchoredPopoverOptions["bounds"];
  /** With `at` and `side: "above"`: boxes it must not cover, and where it opens below instead; see anchored-popover.ts. */
  avoid?: AnchoredPopoverOptions["avoid"];
  atBelow?: number;
  /** An extra class on the menu, for a variant's own sizing. */
  className?: string;
}

/** Opens a menu of actions next to `anchor`, one row per action (icon and label). */
export function openWindowMenu(stage: HTMLElement, anchor: HTMLElement, items: WindowMenuItem[], source: PopoverSource, onClosed: () => void, options: WindowMenuOptions = {}): AnchoredPopover {
  const menu = openAnchoredPopover({
    stage, anchor, label: options.label ?? "Window actions", className: `ui-window-menu ${options.className ?? ""}`.trim(),
    align: options.align ?? "end", maxWidth: options.maxWidth ?? 240,
    ...(options.side ? { side: options.side } : {}), ...(options.hug ? { hug: true } : {}),
    ...(options.at ? { at: options.at } : {}),
    ...(options.atAlign ? { atAlign: options.atAlign } : {}),
    ...(options.bounds ? { bounds: options.bounds } : {}),
    ...(options.avoid ? { avoid: options.avoid } : {}),
    ...(options.atBelow !== undefined ? { atBelow: options.atBelow } : {}),
  }, source, onClosed);
  menu.root.setAttribute("role", "menu");
  const rows: HTMLButtonElement[] = [];
  for (const item of items) {
    if (item.danger && rows.length) {
      const rule = document.createElement("div");
      rule.className = "ui-window-menu-rule";
      rule.setAttribute("role", "separator");
      menu.root.append(rule);
    }
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ui-window-menu-item";
    row.dataset.action = item.id;
    if (item.danger) row.classList.add("is-danger");
    row.setAttribute("role", "menuitem");
    row.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg><span></span>`;
    row.querySelector("span")!.textContent = item.label;
    row.addEventListener("click", (event) => { if (!item.keepOpen) menu.close(event.detail === 0 ? "keyboard" : "pointer"); item.run(event); });
    rows.push(row);
    menu.root.append(row);
  }
  menu.root.addEventListener("keydown", (event) => {
    const at = rows.indexOf(document.activeElement as HTMLButtonElement);
    const to = event.key === "ArrowDown" ? (at + 1) % rows.length : event.key === "ArrowUp" ? (at <= 0 ? rows.length - 1 : at - 1)
      : event.key === "Home" ? 0 : event.key === "End" ? rows.length - 1 : -1;
    if (to < 0) return;
    event.preventDefault();
    rows[to]!.focus({ preventScroll: true });
  });
  menu.place();
  if (source === "keyboard") rows[0]?.focus({ preventScroll: true });
  return menu;
}
