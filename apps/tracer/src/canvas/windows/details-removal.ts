// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The "Remove host" block at the end of the machine card's Connection tab (D385, #486).
 *
 * It is a danger row, like every destructive row (TASTE: "A destructive action is a row"): the short name in the danger
 * colour and, under it, one sentence on what happens, in the order it happens (D219, D273). Pressing it turns the block
 * into the question inside the panel, with no floating card: the host's name, the same sentence, and two buttons,
 * Keep and a red Remove. Escape takes the question back. A pointer press crossfades in about 150 ms on the product
 * ease-out; a keyboard open is instant (TASTE, #427); reduced motion swaps at once.
 *
 * Only the row's confirmation is here. What removing does (revoke, uninstall) is the host-removal adapter's job, reached
 * through `action.runConfirmed`.
 */
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";

/** The card's one destructive action. */
export interface DetailsAction {
  /** The row's short name ("Remove host"). */
  label: string;
  /** What it does, in one sentence. */
  hint: string;
  /** What it acts on ("compute01"), for the question. */
  subject: string;
  /** Does it, once the person has answered in the panel. */
  runConfirmed(): void;
}

/** Matches the CSS-free crossfade below. */
const FADE = 150;
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Builds the block. The caller appends `root` and shows or hides it with the Connection tab. */
export function createRemovalFoot(action: DetailsAction): HTMLElement {
  const root = document.createElement("div");
  root.className = "canvas-popover-action ui-sp-list";
  root.dataset.stacked = "";
  const row = document.createElement("button");
  row.type = "button";
  row.className = "ui-sp-row";
  row.dataset.tone = "danger";
  row.innerHTML = '<span class="ui-sp-text"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span>';
  row.querySelector<HTMLElement>(".ui-sp-label")!.textContent = action.label;
  row.querySelector<HTMLElement>(".ui-sp-hint")!.textContent = action.hint;

  const ask = document.createElement("div");
  ask.className = "canvas-popover-ask";
  ask.setAttribute("role", "group");
  ask.setAttribute("aria-label", `Remove ${action.subject}?`);
  ask.hidden = true;
  ask.innerHTML = '<p class="canvas-popover-ask-q"></p><p class="canvas-popover-ask-effect"></p><div class="canvas-popover-ask-actions"><button type="button" class="ui-button" data-button="secondary" data-keep></button><button type="button" class="ui-button canvas-popover-ask-yes" data-button="primary" data-yes></button></div>';
  ask.querySelector<HTMLElement>(".canvas-popover-ask-q")!.textContent = `Remove ${action.subject}?`;
  ask.querySelector<HTMLElement>(".canvas-popover-ask-effect")!.textContent = action.hint;
  const keep = ask.querySelector<HTMLButtonElement>("[data-keep]")!;
  const yes = ask.querySelector<HTMLButtonElement>("[data-yes]")!;
  keep.textContent = "Keep";
  yes.textContent = "Remove";
  root.append(row, ask);

  /** Swaps the row and the question; `instant` for a keyboard open, otherwise a short ease-out crossfade. */
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
  return root;
}
