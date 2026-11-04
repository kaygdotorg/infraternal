// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Setup progress in the machine pill (D255, #189; TASTE "Progress lives where the thing is").
 *
 * When a new host's shell is ready the window opens with a live prompt and the wizard's status moves into the window's
 * machine pill: a small circle split into the remaining setup stages (setup-ring.ts in packages/ui). Each arc fills as
 * its stage completes (`SetupEvent`s from `setup-stages.ts`), the circle turns into a tick, then into the machine's
 * system icon. A failed stage turns its arc to the failure colour, and pressing the pill explains it in plain words
 * with the next action (the shared anchored confirmation, with a try-again glyph instead of a tick).
 *
 * Invariants:
 * - Typing is never in the way. The flight and every change here are opacity and transform only; the one layout read
 *   per frame during the 280 ms flight is the pill mark's box (the camera may still be moving the window), and nothing
 *   here touches the terminal. No transform stays on anything at rest.
 * - The pill never changes width: the ring lives in the mark's own box.
 * - Nothing is invented from time. Every arc is the server's setup event (setup-stages.ts); only the tick's hold and
 *   the crossfade are timed.
 * - Reduced motion: no flight (the ring fades in in place), no pulse, no scale; fills and the tick fade.
 */
import { createSetupRing, mountConfirmTip, mountSetupRing, type ConfirmTipController, type RingStageState, type SetupRing, type WindowCard } from "../../../../../packages/ui/src/index";
import { failedIndex, foldSetup, freshSetup, setupGuide, SETUP_LABEL, SETUP_STAGES, type SetupEvent, type SetupView } from "./setup-stages";

/** What a source tells besides events. */
export interface SetupSignals {
  /** The server resynchronised: the events that follow are the current stages, so the view starts again. */
  reset?(): void;
  /** The status is unavailable (no stream for this host, or the connection could not be kept). The ring goes quietly. */
  lost?(): void;
}

/** Where setup events come from. A subscriber receives the host's events so far, in order, then the live ones. */
export interface SetupSource {
  subscribe(hostId: string, listener: (event: SetupEvent) => void, signals?: SetupSignals): () => void;
  /** Asks the server to run the failed stage again. Absent when the server cannot. */
  retry?(hostId: string): void;
}

/** What `bindSetupPill` needs: the window's card, the host, and the source of setup events. `from` and `tickHold` only shape the animation. */
export interface SetupPillOptions {
  card: WindowCard;
  /** What the person calls the host, for the popover's words. */
  host: string;
  hostId: string;
  source: SetupSource;
  /** The wizard's status glyph. Its box is where the flight starts; it fades as the flight begins. */
  from?: Element;
  /** How long the tick stays before the system icon returns (ms). Default 600; a mockup can lengthen it to photograph the tick. */
  tickHold?: number;
  /**
   * The host's own removal (the one the palette and machine details use). When setup has run out of attempts the
   * popover offers it, because it is the only way to start over; absent when removal is unavailable.
   */
  remove?: () => { label: string; run(anchor: HTMLElement): void } | undefined;
  /** The server confirmed the host is joined and the final setup stage completed. */
  onComplete?(): void;
}

/** The pill's controls, used by the window that owns the card. */
export interface SetupPill {
  /** The pill was pressed. True when the setup took the press (a failure is explained); false lets the details open. */
  handlePill(source: "pointer" | "keyboard"): boolean;
  /** Whether another setup event can still change the status or offer a retry. */
  isPending(): boolean;
  dispose(): void;
}

/** How long the status glyph takes to fly from the wizard to the pill, in milliseconds. */
const FLIGHT_MS = 280;
/** True when the person asked their system for reduced motion. */
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;
/** Strong ease-out (quartic): fast start, long settle, so the status visibly leaves the wizard at once. */
const easeOut = (t: number): number => 1 - (1 - t) ** 4;
/** Icon paths (a circular arrow) for the popover's "Try again" button. */
const RETRY_ICON = '<path d="M19 12a7 7 0 1 1-2.1-5"/><path d="M19 5.5v5h-5"/>';

/** The ring's stage states for a view; the two types have the same values, so this is a plain read. */
const stagesOf = (view: SetupView): RingStageState[] => view.stages;

/**
 * Shows the host's setup in the window's machine pill. It subscribes to `options.source`, folds each event into the view, repaints the
 * ring, and on a failed stage lets `handlePill` open the explanation (with "Try again", and host removal once attempts run out).
 * A card without a mark gets an inert pill. When the last stage completes it plays the tick, then calls `onComplete`.
 * Call `dispose` when the window closes: it stops the subscription and removes the ring, any flying copy and the popover.
 */
export function bindSetupPill(options: SetupPillOptions): SetupPill {
  const { card, host, hostId, source } = options;
  const mark = card.pill.querySelector<HTMLElement>(".ui-window-mark");
  if (!mark) return { handlePill: () => false, isPending: () => false, dispose() { /* a card without a mark has nothing to show */ } };

  let view = freshSetup();
  const ringPart: SetupRing = mountSetupRing(mark, { segments: SETUP_STAGES.length, label: `Setting up ${host}` });
  let flyer: { box: HTMLElement; ring: SetupRing; frame: number } | undefined;
  let tip: ConfirmTipController | undefined;
  let alive = true;

  const paint = (): void => {
    ringPart.setStages(stagesOf(view));
    flyer?.ring.setStages(stagesOf(view));
    const failed = failedIndex(view) >= 0;
    card.root.dataset.setup = failed ? "failed" : "running";
    const running = view.stages.findIndex((state) => state === "running");
    card.pill.title = ""; // the warm tooltip names it; no native title
    card.pill.dataset.tip = failed ? "Setup needs attention" : running >= 0 ? `${SETUP_LABEL[SETUP_STAGES[running]!]}…` : "";
    if (!card.pill.dataset.tip) delete card.pill.dataset.tip;
  };

  const land = (): void => {
    if (!flyer) return;
    cancelAnimationFrame(flyer.frame);
    // The pill's own ring takes over in the same task the flying copy leaves: the same pixels, so no flash.
    ringPart.show(true, true);
    flyer.box.remove();
    flyer = undefined;
  };

  /** The wizard's status flies into the pill: a copy of the ring moves by transform to wherever the pill's mark is. */
  const fly = (from: Element): void => {
    const start = from.getBoundingClientRect();
    ringPart.show(false, true);
    if (start.width === 0 || reduced()) {
      // No flight to show (or none wanted): the ring simply appears in the pill.
      requestAnimationFrame(() => { if (alive) ringPart.show(true); });
      return;
    }
    const box = document.createElement("div");
    box.className = "ui-setup-fly";
    box.style.width = `${start.width}px`;
    box.style.height = `${start.height}px`;
    const ring = createSetupRing({ segments: SETUP_STAGES.length });
    ring.setStages(stagesOf(view));
    box.append(ring.root);
    document.body.append(box);
    if (from instanceof HTMLElement) from.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, easing: "ease-out", fill: "forwards" });
    const began = performance.now();
    const step = (now: number): void => {
      if (!alive || !flyer) return;
      const target = mark.getBoundingClientRect();
      if (target.width === 0) { land(); return; }
      const t = Math.min(1, (now - began) / FLIGHT_MS);
      const k = easeOut(t);
      const x = start.left + (target.left - start.left) * k;
      const y = start.top + (target.top - start.top) * k;
      const scale = 1 + (target.width / start.width - 1) * k;
      box.style.transform = `translate3d(${x}px, ${y}px, 0) scale(${scale})`;
      if (t >= 1) land(); else flyer.frame = requestAnimationFrame(step);
    };
    flyer = { box, ring, frame: 0 };
    // Placed at the source before the first frame paints, so the copy appears exactly over the wizard's glyph.
    box.style.transform = `translate3d(${start.left}px, ${start.top}px, 0)`;
    flyer.frame = requestAnimationFrame(step);
  };

  paint();
  if (options.from) fly(options.from);

  const finish = (): void => {
    // The ring says "done" by itself: circle, tick, hold, system icon. The window then carries no setup state.
    void ringPart.complete(options.tickHold === undefined ? {} : { hold: options.tickHold }).then(() => { if (alive) { delete card.root.dataset.setup; delete card.pill.dataset.tip; } });
  };
  const stop = source.subscribe(hostId, (event) => {
    if (!alive) return;
    const was = view.complete;
    const previousRetry = view.retryAvailable;
    view = foldSetup(view, event);
    paint();
    // A retry starts again after a failure: the explanation no longer applies.
    if (tip && (failedIndex(view) < 0 || previousRetry !== view.retryAvailable)) { tip.close(false); tip = undefined; }
    if (view.complete && !was) {
      // A flight still in the air lands first, so the tick never starts under a copy that is still travelling.
      land();
      finish();
      options.onComplete?.();
    }
  }, {
    reset() { if (alive) { view = freshSetup(); paint(); } },
    lost() {
      // No status to show: a failure already explained stays (it is news); a ring that can no longer learn anything fades out.
      if (!alive || failedIndex(view) >= 0 || view.complete) return;
      land();
      ringPart.show(false);
      delete card.root.dataset.setup;
      delete card.pill.dataset.tip;
      window.setTimeout(() => { if (alive) ringPart.dispose(); }, 240);
    },
  });

  return {
    isPending() { return !view.complete; },
    handlePill() {
      if (failedIndex(view) < 0) return false;
      if (tip) { tip.close(false); tip = undefined; return true; }
      const guide = setupGuide(host, view);
      // Asked when the popover opens: the removal's label arrives from the server after the window does.
      const removal = view.retryAvailable === false ? options.remove?.() : undefined;
      tip = mountConfirmTip(card.pill, {
        label: `Setup of ${host}`,
        title: guide.title,
        effect: guide.effect,
        confirmLabel: "Try again",
        confirmDisabled: view.retryAvailable === false || !source.retry,
        cancelLabel: "Dismiss",
        confirmIcon: RETRY_ICON,
        named: !!removal,
        ...(removal ? { secondary: { label: removal.label, onSelect: () => { tip = undefined; removal.run(card.pill); } } } : {}),
        boundary: card.root,
        onConfirm: () => { tip = undefined; if (view.retryAvailable !== false) source.retry?.(hostId); },
        onCancel: () => { tip = undefined; },
      });
      return true;
    },
    dispose() {
      alive = false;
      stop();
      land();
      tip?.close(false);
      ringPart.dispose();
      delete card.root.dataset.setup;
    },
  };
}

/** The real stream's client travels with the pill: both load only while a host is setting up. */
export { createSetupFeed } from "./setup-feed";
