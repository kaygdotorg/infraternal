// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The in-row confirmation (TASTE "A destructive row action asks in its own row", #242): a destructive action on a
 * list row asks in the row itself. The row's own text crossfades into the question and its two answers, "End session?
 * End · Cancel", at the row's own height, so nothing around it moves and no dialog or floating card exists.
 *
 * - The question sits over the row's leaf; the leaf keeps its box, so the row's height and its neighbours' positions are the
 *   same before, during and after. The leaf is `inert` while the question is up, and its marker (the status dot) stays where
 *   it is: only the leaf's text fades. The question starts exactly where the row's own label starts (`alignTo`, measured as
 *   the label's offset inside the leaf, so a swipe in flight or a press scale does not move it), on the same centre line and
 *   in the same size, so the row reads as the same row with its words turned into a question (TASTE "Replacements start
 *   where what they replace starts").
 * - Keyboard: a question opened from the keyboard lands on the confirm word, with no motion (keyboard-opened surfaces
 *   stay instant, TASTE). Left and Right move between the two words, Enter or Space picks the focused one (a held
 *   Enter never repeats), Escape cancels and gives the focus back to the row. Tab leaves the question, which cancels it.
 * - Anything else cancels and puts the row back as it was: Cancel, Escape, a press outside the question, the focus
 *   moving away, the row leaving the page. Where the action cannot be undone, the answer is the only step: the effect
 *   line is read out to screen readers (`aria-describedby`) and is not drawn, so the row never grows.
 * - Pointer and touch: a short crossfade (about 150 ms), interruptible. Reduced motion swaps at once.
 *
 * The component knows nothing about what a row is. `row-menu.ts` mounts it for an action that says it `confirm`s.
 */

export interface RowAskOptions {
  /** The accessible name of the question group, e.g. "End 'deploy'?". */
  label: string;
  /** What the row says, e.g. "End session?". */
  question: string;
  /** The row's own label: the question starts where it starts. Absent, the question starts at the row's own padding. */
  alignTo?: Element | null;
  /** What it says when the row is too narrow for `question` to show whole ("End?"). Never an ellipsis: a cut-off question is not a question. */
  shortQuestion?: string;
  /** What changes for the person, read out with the question (never drawn). */
  effect?: string;
  /** The answer that does it, by name: "End". */
  confirmLabel: string;
  /** The way out, by name: "Cancel". */
  cancelLabel: string;
  /** Opened from the keyboard: instant, and the focus lands on the confirm word. */
  keyboard?: boolean;
  onConfirm(): void;
  onCancel(): void;
}

export interface RowAsk {
  /** Puts the row back. `restoreFocus` returns the focus to the row's leaf when it was inside the question. */
  close(restoreFocus?: boolean): void;
}

const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;
/** The crossfade, matching the CSS (`.ui-row-ask`). */
const FADE = 160;

let serial = 0;

export function mountRowAsk(row: HTMLElement, leaf: HTMLElement, options: RowAskOptions): RowAsk {
  const id = `ui-row-ask-${++serial}`;
  const ask = document.createElement("div");
  ask.className = "ui-row-ask";
  ask.setAttribute("role", "group");
  ask.setAttribute("aria-label", options.label);
  if (options.effect) ask.setAttribute("aria-describedby", `${id}-effect`);

  const question = document.createElement("span");
  question.className = "ui-row-ask-q";
  question.textContent = options.question;
  const yes = document.createElement("button");
  yes.type = "button";
  yes.className = "ui-row-ask-yes";
  yes.textContent = options.confirmLabel;
  const dot = document.createElement("span");
  dot.className = "ui-row-ask-dot";
  dot.setAttribute("aria-hidden", "true");
  dot.textContent = "·";
  const no = document.createElement("button");
  no.type = "button";
  no.className = "ui-row-ask-no";
  no.textContent = options.cancelLabel;
  ask.append(question, yes, dot, no);
  if (options.effect) {
    const effect = document.createElement("span");
    effect.id = `${id}-effect`;
    effect.className = "ui-row-ask-effect";
    effect.textContent = options.effect;
    ask.append(effect);
  }

  // Where the label starts inside the leaf. Both rects share whatever transform the leaf has, so their difference does not.
  if (options.alignTo?.isConnected) ask.style.paddingLeft = `${options.alignTo.getBoundingClientRect().left - leaf.getBoundingClientRect().left}px`;

  const instant = Boolean(options.keyboard) || reduced();
  if (instant) ask.dataset.instant = "";
  row.dataset.asking = "";
  leaf.inert = true;
  row.append(ask);
  // Laid out closed first, so the crossfade has a start.
  void ask.offsetWidth;
  // The whole line is measured, not the question alone: the answers follow it on the same line and must stay inside the row.
  if (options.shortQuestion && ask.scrollWidth > ask.clientWidth + 0.5) question.textContent = options.shortQuestion;
  ask.dataset.open = "";
  if (options.keyboard) yes.focus({ preventScroll: true });

  let done = false;
  const controller = new AbortController();
  const { signal } = controller;

  const finish = (restoreFocus: boolean): void => {
    if (done) return;
    done = true;
    controller.abort();
    const hadFocus = ask.contains(document.activeElement);
    delete row.dataset.asking;
    leaf.inert = false;
    delete ask.dataset.open;
    // The question stays in the page until the key press that closed it has gone through every listener: the sidebar's and
    // the canvas's own Escape handlers look for it (`.ui-row-ask`) to know that this Escape was already taken.
    window.setTimeout(() => ask.remove(), instant ? 0 : FADE + 20);
    if (restoreFocus && (hadFocus || options.keyboard) && leaf.isConnected) leaf.focus({ preventScroll: true });
  };
  const cancel = (restoreFocus: boolean): void => {
    if (done) return;
    finish(restoreFocus);
    options.onCancel();
  };
  const confirm = (): void => {
    if (done) return;
    finish(false);
    options.onConfirm();
  };

  yes.addEventListener("click", (event) => { event.stopPropagation(); confirm(); }, { signal });
  no.addEventListener("click", (event) => { event.stopPropagation(); cancel(true); }, { signal });
  // The row's own click handlers (opening the session) must not hear a press on the question.
  ask.addEventListener("click", (event) => event.stopPropagation(), { signal });

  window.addEventListener("keydown", (event) => {
    if (!row.isConnected) { cancel(false); return; }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      cancel(true);
      return;
    }
    if (!ask.contains(document.activeElement)) return;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      event.stopPropagation();
      (document.activeElement === yes ? no : yes).focus({ preventScroll: true });
    } else if ((event.key === "Enter" || event.key === " ") && event.repeat) {
      // A held Enter that opened the question must never also answer it.
      event.preventDefault();
    }
  }, { signal, capture: true });
  // A press anywhere else is a "no", and still goes where it was aimed.
  document.addEventListener("pointerdown", (event) => {
    if (event.target instanceof Node && !ask.contains(event.target)) cancel(false);
  }, { signal, capture: true });
  // The focus moving away (Tab past the last word) is a "no" too.
  ask.addEventListener("focusout", (event) => {
    const next = event.relatedTarget;
    if (next instanceof Node && !ask.contains(next)) cancel(false);
  }, { signal });

  return { close: (restoreFocus = false) => { if (!done) finish(restoreFocus); } };
}
