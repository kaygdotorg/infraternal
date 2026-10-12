/**
 * The anchored actions menu (TASTE: title first). A narrow window's ⋯ opens its actions here, and the sidebar's profile
 * pill opens its menu (Settings, Sign out) here too: one menu, one material, one set of rows. Loaded when a menu is
 * first opened (D188): a window that is not narrow never needs it, so the card that every window draws does not carry
 * the popover.
 *
 * Keyboard: opened by keyboard, focus lands on the first row; ↑ and ↓ walk the rows, Home and End jump, Escape closes
 * and returns to the anchor. A press on a row closes the menu first, then runs the action.
 */
import { openAnchoredPopover, type AnchoredPopover, type PopoverSource } from "./anchored-popover";

export interface WindowMenuItem { id: string; label: string; icon: string; run(event: MouseEvent): void }

export interface WindowMenuOptions {
  /** The dialog's accessible name. Default "Window actions". */
  label?: string;
  side?: "below" | "above";
  align?: "start" | "end";
  /** Size to the rows instead of the full width (a short menu). */
  hug?: boolean;
  maxWidth?: number;
}

/** Opens a menu of actions next to `anchor`, one row per action (icon and label). */
export function openWindowMenu(stage: HTMLElement, anchor: HTMLElement, items: WindowMenuItem[], source: PopoverSource, onClosed: () => void, options: WindowMenuOptions = {}): AnchoredPopover {
  const menu = openAnchoredPopover({
    stage, anchor, label: options.label ?? "Window actions", className: "ui-window-menu",
    align: options.align ?? "end", maxWidth: options.maxWidth ?? 240,
    ...(options.side ? { side: options.side } : {}), ...(options.hug ? { hug: true } : {}),
  }, source, onClosed);
  menu.root.setAttribute("role", "menu");
  const rows: HTMLButtonElement[] = [];
  for (const item of items) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ui-window-menu-item";
    row.dataset.action = item.id;
    row.setAttribute("role", "menuitem");
    row.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg><span></span>`;
    row.querySelector("span")!.textContent = item.label;
    row.addEventListener("click", (event) => { menu.close(event.detail === 0 ? "keyboard" : "pointer"); item.run(event); });
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
