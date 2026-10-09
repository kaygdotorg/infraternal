/**
 * The toolbar's canvas row (touch) and the desktop buttons beside the top pill: the same canvas actions in both
 * places (D177). Row items: search, views, previous and next window, canvas lock, overview, input lock, split
 * right and down, sessions (only with an inventory), add host (only when the flow exists), sidebar. Items disable while the input lock is on, and
 * the splits when the active window is not a terminal.
 */
import { ICONS, iconSvg } from "../../../../../packages/ui/src/icons";
import { isMacPlatform } from "../../../../../packages/ui/src/platform";
import { refreshTip } from "../../../../../packages/ui/src/tooltip";
import type { ToolbarItem, ToolbarRow } from "../../core-screen";
import type { Ctx } from "../context";
import { el } from "../dom";
import { isTerminal } from "../views/body";
import { SESSION_ICON } from "../views/icons";
import { bindingText } from "./shortcuts";

export interface ToolbarModule {
  /** Repaints item state (lock, selection) from the shared state. */
  update(): void;
  dispose(): void;
}

export function createToolbar(cx: Ctx): ToolbarModule {
  const { stage, signal, state, core } = cx;
  const openPalette = (): void => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: isMacPlatform(), ctrlKey: !isMacPlatform(), bubbles: true })); };

  // Desktop: the canvas lock toggle and the view switcher sit next to the top pill.
  const lockBtn = el("button", "ui-pill ui-pill-icon cl-snap");
  lockBtn.type = "button";
  lockBtn.innerHTML = iconSvg("snap");
  const viewsBtn = el("button", "ui-pill ui-pill-icon cl-viewsbtn");
  viewsBtn.type = "button";
  viewsBtn.innerHTML = iconSvg("views");
  viewsBtn.setAttribute("aria-label", "Views");
  viewsBtn.dataset.tip = "Views";
  stage.querySelector(".tabs")?.prepend(viewsBtn, lockBtn);
  lockBtn.addEventListener("click", () => cx.nav.setCanvasLock(!state.canvasLock), { signal });
  viewsBtn.addEventListener("click", () => cx.viewList.toggle(), { signal });

  // The "+" beside the top pill opens a new shell window on the first host.
  const add = stage.querySelector<HTMLButtonElement>(".tab-add");
  if (add) {
    add.disabled = false;
    add.setAttribute("aria-label", "New window");
    add.dataset.tip = "New window";
    add.addEventListener("click", () => { const host = cx.adapters.sessions.hosts()[0]; if (host) cx.win.open(host.name); }, { signal });
  }

  const splitActive = (direction: "right" | "down"): void => { const w = state.activeWin; if (w && w.model.kind === "terminal") void cx.win.split(w, direction); };
  /** The session manager of the active window, from its own action (the card places the popover under it). */
  const openSessions = (): void => {
    const w = state.activeWin;
    const anchor = w?.card.header.querySelector<HTMLButtonElement>("[data-action='sessions']");
    if (w && anchor && isTerminal(w)) cx.sessionUi?.toggleManager(w, anchor, "pointer");
  };
  const items: ToolbarItem[] = [
    { id: "search", label: "Search and actions", icon: ICONS.search, onSelect: openPalette },
    { id: "views", label: "Views", icon: ICONS.views, onSelect: () => cx.viewList.toggle() },
    { id: "previous", label: "Previous window", icon: ICONS.previous, onSelect: () => { if (!cx.inputLock.state) cx.win.step(-1); } },
    { id: "next", label: "Next window", icon: ICONS.next, onSelect: () => { if (!cx.inputLock.state) cx.win.step(1); } },
    { id: "canvas-lock", label: "Canvas lock", icon: ICONS.snap, pressed: true, onSelect: () => { if (!cx.inputLock.state) cx.nav.setCanvasLock(!state.canvasLock); } },
    { id: "overview", label: "All views", icon: ICONS.overview, onSelect: () => { if (!cx.inputLock.state) cx.nav.showOverview(); } },
    { id: "input-lock", label: "Input lock", icon: ICONS.lock, onSelect: () => cx.inputLock.toggle() },
    { id: "split-right", label: "Split right", icon: ICONS.splitRight, onSelect: () => splitActive("right") },
    { id: "split-down", label: "Split down", icon: ICONS.splitDown, onSelect: () => splitActive("down") },
    ...(cx.adapters.inventory ? [{ id: "sessions", label: "Sessions", icon: SESSION_ICON.sessions, onSelect: openSessions }] : []),
    ...(cx.adapters.addHost ? [{ id: "add", label: "Add host", icon: ICONS.plus, onSelect: () => cx.adapters.addHost?.() }] : []),
    { id: "sidebar", label: "Sidebar", icon: ICONS.sidebar, onSelect: () => stage.querySelector<HTMLButtonElement>("#sidebar-toggle")?.click() },
  ];
  const row: ToolbarRow = core.setCanvasRow(items);

  const update = (): void => {
    const locked = Boolean(cx.inputLock.state);
    const terminal = Boolean(state.activeWin && isTerminal(state.activeWin));
    lockBtn.setAttribute("aria-pressed", String(state.canvasLock));
    lockBtn.dataset.tip = `${state.canvasLock ? "Canvas lock on" : "Canvas lock off"} (${bindingText("canvas-lock")})`;
    lockBtn.setAttribute("aria-label", lockBtn.dataset.tip);
    refreshTip(lockBtn);
    row.update("canvas-lock", { pressed: state.canvasLock, label: state.canvasLock ? "Canvas lock on" : "Canvas lock off", disabled: locked });
    row.update("previous", { disabled: locked });
    row.update("next", { disabled: locked });
    row.update("overview", { disabled: locked });
    row.update("input-lock", { pressed: locked, disabled: !terminal && !locked, label: locked ? "Input lock on" : "Input lock off", icon: locked ? ICONS.lock : ICONS.unlock });
    row.update("split-right", { disabled: !terminal });
    row.update("split-down", { disabled: !terminal });
    if (cx.adapters.inventory) row.update("sessions", { disabled: !terminal });
  };
  const offLock = cx.nav.onLockChange(update);
  update();
  return { update, dispose() { offLock(); row.dispose(); lockBtn.remove(); viewsBtn.remove(); if (add) { add.disabled = true; add.removeAttribute("data-tip"); } } };
}
