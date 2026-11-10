// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Review variants for how the machine details card offers "Remove host" (#486). The owner picks one; the other two are then
 * deleted together with this file. Nothing here is final.
 *
 * The default (`foot`) lives in `details.on-demand.ts`. The two others load from here only when the page is opened with
 * `?removalui=menu` or `?removalui=inline`:
 *
 * - **menu**: the action is not on the card's face at all. A quiet ⋯ button at the right of the card's header opens the
 *   shared actions menu, whose one entry, "Remove host…", opens the same glass confirmation card (D380) as the default.
 *   The ellipsis in the entry says a question follows.
 * - **inline**: a danger row under the facts, like the default, but pressing it turns the row into the question in the
 *   panel itself: the host's name, what happens ("Revokes its access, then uninstalls the infraternal agent from it.") and
 *   two buttons, Remove and Keep. No floating card. The foot crossfades in about 150 ms; a keyboard open is instant.
 *
 * Both say plainly what removal does, in the order it happens (D219, D273), and use only shared pieces: the window menu, the
 * settings row, `ui-button`, the product ease-out.
 */
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import { openWindowMenu } from "../../../../../packages/ui/src/window-menu.on-demand";
import type { DetailsAction } from "./details.on-demand";

/** A trash can on the 24 px grid; the shared icon set has none yet. */
const ICON_REMOVE = '<path d="M5 7.5h14M9.5 7.5V5.5h5v2M7 7.5l.8 11h8.4l.8-11M10.5 11v4.5M13.5 11v4.5"/>';
/** The ⋯ glyph the window card's own overflow button uses. */
const ICON_DOTS = '<path d="M5 12h.01M12 12h.01M19 12h.01"/>';
/** Matches the CSS crossfade of the inline question (`.canvas-popover-ask`). */
const FADE = 150;

const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Adds the chosen variant to the open details card `root`. `stage` is the screen the menu floats over. */
export function mountRemovalVariant(root: HTMLElement, variant: "menu" | "inline", action: DetailsAction, stage: HTMLElement): void {
  if (variant === "menu") mountMenu(root, action, stage); else mountInline(root, action);
}

/** Variant "menu": a ⋯ button in the header, a menu with one entry, then the glass confirmation card. */
function mountMenu(root: HTMLElement, action: DetailsAction, stage: HTMLElement): void {
  const head = root.querySelector<HTMLElement>(".canvas-popover-head");
  if (!head) return;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "canvas-popover-more ui-window-action";
  button.setAttribute("aria-label", "Host actions");
  button.setAttribute("aria-haspopup", "menu");
  button.dataset.tip = "Host actions";
  button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON_DOTS}</svg>`;
  button.addEventListener("click", () => {
    openWindowMenu(stage, button, [{ id: "remove-host", label: `${action.label}…`, icon: ICON_REMOVE, danger: true, run: () => action.run(button) }], triggeredByKeyboard() ? "keyboard" : "pointer", () => {}, { label: "Host actions", hug: true, align: "end" });
  });
  head.append(button);
}

/** Variant "inline": the foot row becomes the question inside the panel. */
function mountInline(root: HTMLElement, action: DetailsAction): void {
  const foot = document.createElement("div");
  foot.className = "canvas-popover-action ui-sp-list";
  foot.dataset.stacked = "";
  const row = document.createElement("button");
  row.type = "button";
  row.className = "ui-sp-row";
  row.dataset.tone = "danger";
  row.innerHTML = '<span class="ui-sp-text"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span>';
  row.querySelector<HTMLElement>(".ui-sp-label")!.textContent = action.label;
  row.querySelector<HTMLElement>(".ui-sp-hint")!.textContent = action.hint ?? "";

  const ask = document.createElement("div");
  ask.className = "canvas-popover-ask";
  ask.setAttribute("role", "group");
  ask.setAttribute("aria-label", `Remove ${action.subject}?`);
  ask.hidden = true;
  ask.innerHTML = '<p class="canvas-popover-ask-q"></p><p class="canvas-popover-ask-effect"></p><div class="canvas-popover-ask-actions"><button type="button" class="ui-button" data-button="secondary" data-keep></button><button type="button" class="ui-button canvas-popover-ask-yes" data-button="primary" data-yes></button></div>';
  ask.querySelector<HTMLElement>(".canvas-popover-ask-q")!.textContent = `Remove ${action.subject}?`;
  ask.querySelector<HTMLElement>(".canvas-popover-ask-effect")!.textContent = action.hint ?? "";
  const keep = ask.querySelector<HTMLButtonElement>("[data-keep]")!;
  const yes = ask.querySelector<HTMLButtonElement>("[data-yes]")!;
  keep.textContent = "Keep";
  yes.textContent = "Remove";
  foot.append(row, ask);
  root.append(foot);

  /** Swaps the row and the question; `instant` for a keyboard open (no motion), otherwise a short ease-out crossfade. */
  const swap = (asking: boolean, instant: boolean): void => {
    const [from, to] = asking ? [row, ask] : [ask, row];
    from.hidden = true;
    to.hidden = false;
    if (!instant && !reduced()) to.animate([{ opacity: 0 }, { opacity: 1 }], { duration: FADE, easing: EASE_OUT });
    (asking ? keep : row).focus({ preventScroll: true });
  };
  row.addEventListener("click", () => swap(true, triggeredByKeyboard()));
  keep.addEventListener("click", () => swap(false, triggeredByKeyboard()));
  yes.addEventListener("click", () => action.runConfirmed());
  ask.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    // The panel's own Escape would close the whole card; this one only takes the question back.
    event.stopPropagation();
    swap(false, true);
  });
}
