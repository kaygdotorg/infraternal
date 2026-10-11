/**
 * The collapsed window actions menu (TASTE: title first). A narrow window's ⋯ opens its actions here, in the anchored
 * popover. Loaded when the ⋯ is first pressed (D188): a window that is not narrow never needs it, so the card that every
 * window draws does not carry the popover.
 */
import { openAnchoredPopover, type AnchoredPopover, type PopoverSource } from "./anchored-popover";

export interface WindowMenuItem { id: string; label: string; icon: string; run(event: MouseEvent): void }

/** Opens the actions of a window's header menu under its ⋯ button, one row per action (icon and label). */
export function openWindowMenu(stage: HTMLElement, anchor: HTMLElement, items: WindowMenuItem[], source: PopoverSource, onClosed: () => void): AnchoredPopover {
  const menu = openAnchoredPopover({ stage, anchor, label: "Window actions", className: "ui-window-menu", align: "end", maxWidth: 240 }, source, onClosed);
  for (const item of items) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ui-window-menu-item";
    row.dataset.action = item.id;
    row.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg><span></span>`;
    row.querySelector("span")!.textContent = item.label;
    row.addEventListener("click", (event) => { menu.close("pointer"); item.run(event); });
    menu.root.append(row);
  }
  menu.place();
  return menu;
}
