// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The "Remove host" block at the end of the machine card's Connection tab (D385, #486).
 *
 * It is a danger row, like every destructive row (TASTE: "A destructive action is a row"): the short name in the danger
 * colour and, under it, one sentence on what happens, in the order it happens (D219, D273). Pressing it turns the block
 * into the question inside the panel, with no floating card: the host's name, the same sentence, and two buttons,
 * Keep and a red Remove. A pointer press crossfades in about 150 ms on the product ease-out; a keyboard open is instant
 * (TASTE, #427); reduced motion swaps at once.
 *
 * The block is a small state machine, and every state says something (it never fails or refuses silently):
 * - `row`: the danger row.
 * - `asking`: the question. Keep or Escape put the row back and give it the focus. Leaving the tab resets it (`reset`).
 * - `pending`: Remove was pressed. Both buttons are disabled, Remove reads "Removing…", and the focus moves to the
 *   question itself so it is never lost to a disabled button. The question's note (a polite live region) says it.
 * - `done`: it worked (removed, or access revoked with the uninstall waiting for the machine). The note says which.
 * - failed or refused: the note says why, in the danger colour, as an alert; Remove is live again and reads "Try again".
 * - The host's own state (`status`, read on every `sync`): offline adds a line saying the uninstall waits until the machine
 *   connects; gone (already removed elsewhere) turns the question into a note and disables it.
 *
 * What removing does (revoke, uninstall) is the host-removal adapter's job, reached through `action.runConfirmed`.
 */
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import type { RemovalOutcome } from "../context";

/** Whether the machine can be reached for removal right now: `offline` still allows it (the uninstall waits), `gone` does not. */
export type RemovalStatus = "ready" | "offline" | "gone";

/** The card's one destructive action. */
export interface DetailsAction {
  /** The row's short name ("Remove host"). */
  label: string;
  /** What it does, in one sentence. */
  hint: string;
  /** What it acts on ("compute01"), for the question. */
  subject: string;
  /** The host's state now; read on every sync, so a host that goes offline or is removed while the question is open shows. Absent means ready. */
  status?(): RemovalStatus;
  /** Does it, once the person has answered in the panel, and says how it ended. */
  runConfirmed(): Promise<RemovalOutcome>;
}

/** What the card needs from the block. */
export interface RemovalFoot {
  /** The element to append; the caller shows or hides it with the Connection tab. */
  readonly root: HTMLElement;
  /** Puts an open question back to the row (a tab change). A removal already running or finished keeps its state. */
  reset(): void;
  /** Re-reads the host's state and updates the sentence and the question to match. */
  sync(): void;
  /** Called with the outcome of a confirmed removal, once; the card uses it to close itself after a removal. */
  onOutcome?: (outcome: RemovalOutcome) => void;
}

/** The crossfade between row and question, matching the product's pop speed. */
const FADE = 150;
/** Whether the person asked for reduced motion; the question then swaps without a fade. */
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

type Phase = "row" | "asking" | "pending" | "done";

/** Builds the block. */
export function createRemovalFoot(action: DetailsAction): RemovalFoot {
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
  ask.tabIndex = -1;
  ask.hidden = true;
  // The panel closes on Escape unless the focused pane owns it (details.on-demand.ts): here Escape only takes the question back.
  ask.dataset.ownsEscape = "";
  ask.innerHTML = '<p class="canvas-popover-ask-q"></p><p class="canvas-popover-ask-effect"></p><p class="canvas-popover-ask-note" role="status" aria-live="polite" hidden></p><div class="canvas-popover-ask-actions"><button type="button" class="ui-button" data-button="secondary" data-keep></button><button type="button" class="ui-button canvas-popover-ask-yes" data-button="primary" data-yes></button></div>';
  const question = ask.querySelector<HTMLElement>(".canvas-popover-ask-q")!;
  const effect = ask.querySelector<HTMLElement>(".canvas-popover-ask-effect")!;
  const note = ask.querySelector<HTMLElement>(".canvas-popover-ask-note")!;
  const keep = ask.querySelector<HTMLButtonElement>("[data-keep]")!;
  const yes = ask.querySelector<HTMLButtonElement>("[data-yes]")!;
  question.textContent = `Remove ${action.subject}?`;
  keep.textContent = "Keep";
  yes.textContent = "Remove";
  root.append(row, ask);

  let phase: Phase = "row";
  const foot: RemovalFoot = { root, reset, sync };

  /** Says something in the note: `alert` for a failure (read at once, in the danger colour), otherwise a polite status. */
  function say(text: string, alert = false): void {
    note.textContent = text;
    note.hidden = text === "";
    note.dataset.tone = alert ? "danger" : "";
    note.setAttribute("role", alert ? "alert" : "status");
  }
  /** Shows the row or the question; `instant` for a keyboard open, otherwise a short ease-out crossfade. */
  function show(asking: boolean, instant: boolean, focus: boolean): void {
    const [from, to] = asking ? [row, ask] : [ask, row];
    from.hidden = true;
    to.hidden = false;
    if (!instant && !reduced()) to.animate([{ opacity: 0 }, { opacity: 1 }], { duration: FADE, easing: EASE_OUT });
    if (focus) (asking ? keep : row).focus({ preventScroll: true });
  }
  /** Back to the row, from the question; the note and the buttons start clean the next time. */
  function reset(): void {
    if (phase !== "asking") return;
    phase = "row";
    say("");
    yes.textContent = "Remove";
    row.hidden = false;
    ask.hidden = true;
  }
  function sync(): void {
    const status = action.status?.() ?? "ready";
    effect.textContent = status === "offline" ? `${action.hint} ${action.subject} is offline, so the uninstall waits until it connects.` : action.hint;
    if (status === "gone" && phase !== "done") {
      // Removed elsewhere while the question was open: nothing is left to remove, so say so and take the answers away.
      if (phase === "row") { root.dataset.gone = ""; return; }
      phase = "done";
      say(`${action.subject} is already removed.`);
      yes.disabled = true;
      keep.disabled = true;
    }
  }

  row.addEventListener("click", () => {
    if (phase !== "row") return;
    phase = "asking";
    sync();
    show(true, triggeredByKeyboard(), true);
  });
  const back = (instant: boolean): void => {
    if (phase !== "asking") return;
    phase = "row";
    say("");
    yes.textContent = "Remove";
    show(false, instant, true);
  };
  keep.addEventListener("click", () => back(triggeredByKeyboard()));
  ask.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || phase !== "asking") return;
    // The panel's own Escape would close the whole card; this one only takes the question back.
    event.stopPropagation();
    back(true);
  });
  yes.addEventListener("click", () => {
    if (phase !== "asking") return;
    phase = "pending";
    say("Removing…");
    yes.disabled = true;
    keep.disabled = true;
    yes.textContent = "Removing…";
    ask.setAttribute("aria-busy", "true");
    // A disabled button gives up the focus; the question itself keeps it, so the screen reader and the keyboard stay here.
    ask.focus({ preventScroll: true });
    void action.runConfirmed().then((outcome) => {
      ask.removeAttribute("aria-busy");
      if (outcome.state === "removed" || outcome.state === "pending") {
        phase = "done";
        say(outcome.message);
        yes.textContent = "Remove";
      } else {
        // Failed or never started: the reason stays in the panel, and the person may try again or keep the host.
        phase = "asking";
        say(outcome.message, true);
        yes.disabled = false;
        keep.disabled = false;
        yes.textContent = "Try again";
        yes.focus({ preventScroll: true });
      }
      foot.onOutcome?.(outcome);
    });
  });
  return foot;
}
