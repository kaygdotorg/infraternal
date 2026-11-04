/**
 * One step transition for every multi-step card (D160): the add-host wizard
 * today, the sign-in card next.
 *
 * - The viewport's height follows a spring from wherever it currently is, so a
 *   step change during a transition retargets smoothly instead of snapping.
 * - The outgoing pane and the incoming pane overlap. Each pane rides its own
 *   spring along a "slot" axis: -1 (left, gone), 0 (centred, visible),
 *   +1 (right, gone). Continue moves the old pane to -1 and brings the new one
 *   in from +1; Back mirrors it. Interrupting simply retargets the springs.
 * - Outgoing panes are absolutely positioned in the viewport (a stacking
 *   wrapper), so layout never jumps while both are present.
 * - Crisp text: at rest a pane's transform and opacity are removed entirely and
 *   the viewport returns to `height: auto` and visible overflow, so settled text
 *   sits on no transformed or clipped layer.
 * - Reduced motion: an opacity crossfade only, with no movement or height glide.
 */
import { Spring } from "./spring";

/** Which way a step moves: 1 forward, -1 back, 0 replace in place (crossfade). */
export type StepDirection = 1 | -1 | 0;

/** How far (px) a pane travels sideways between its slot positions. */
const SLIDE = 20;
/** Spring timing of a pane's slide. */
const PANE_SPRING = { visualDuration: 0.34 } as const;
/** Spring timing of the viewport's height. */
const HEIGHT_SPRING = { visualDuration: 0.36 } as const;

/**
 * Switches between the panes of a multi-step card with a slide and a height glide.
 * Give it the viewport element that holds the panes; call {@link PaneStepper.show} for each step.
 * @example
 * const stepper = new PaneStepper(card.querySelector(".steps")!); stepper.show(paneOne, 0); stepper.show(paneTwo, 1);
 */
export class PaneStepper {
  /** The pane on screen or arriving. */
  private current: HTMLElement | undefined;
  /** One slot spring per pane that is on screen; a pane is removed from the DOM and from here when it has left. */
  private readonly panes = new Map<HTMLElement, Spring>();
  /** Drives the viewport height while a step is moving. */
  private readonly height: Spring;
  /** True while the viewport's height is being driven (and `is-moving` is set). */
  private moving = false;
  /** The height (px) the glide is heading to. */
  private goal = 0;

  /** Takes the viewport element and marks it with `ui-pane-viewport`. */
  constructor(private readonly viewport: HTMLElement) {
    viewport.classList.add("ui-pane-viewport");
    this.height = new Spring(0, (value) => {
      if (!this.moving) return;
      this.viewport.style.height = `${value}px`;
      if (value === this.goal) this.settleHeight();
    }, HEIGHT_SPRING);
  }

  /** The pane on screen (or arriving). */
  get active(): HTMLElement | undefined { return this.current; }

  /** Shows `pane`, moving in `direction` (1 forward, -1 back, 0 replace in place). */
  show(pane: HTMLElement, direction: StepDirection): void {
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const from = this.viewport.getBoundingClientRect().height;
    const old = this.current;
    pane.classList.add("ui-pane");
    this.viewport.append(pane);
    this.current = pane;
    if (!old) { this.track(pane, 0, true); return; }

    // Leave in a stacking layer at its current spot so the new pane takes the flow.
    old.classList.add("is-leaving");
    old.inert = true;
    if (reduce || direction === 0) {
      this.crossfade(old, pane);
    } else {
      this.track(pane, direction, true);
      this.slotOf(pane).set(0);
      this.slotOf(old).set(-direction);
    }
    this.glideHeight(from, reduce);
  }

  /** Fades `old` out and `pane` in without movement (reduced motion, or `direction` 0). */
  private crossfade(old: HTMLElement, pane: HTMLElement): void {
    this.panes.get(old)?.set(0, true);
    old.style.transform = "";
    old.animate([{ opacity: getComputedStyle(old).opacity }, { opacity: 0 }], { duration: 160, easing: "ease-out" }).onfinish = () => this.drop(old);
    pane.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" });
    this.track(pane, 0, true);
  }

  /** The slot spring of `pane`, created at the centre when it has none. */
  private slotOf(pane: HTMLElement): Spring {
    return this.panes.get(pane) ?? this.track(pane, 0, true);
  }

  /** Gives `pane` its slot spring, starting at `slot`. */
  private track(pane: HTMLElement, slot: number, instant: boolean): Spring {
    const enter = slot;
    const spring = new Spring(slot, (value) => {
      if (value === 0 && pane === this.current) {
        pane.style.transform = "";
        pane.style.opacity = "";
        return;
      }
      if (pane !== this.current && Math.abs(value) >= 1) { this.drop(pane); return; }
      pane.style.transform = `translate3d(${value * SLIDE}px, 0, 0)`;
      // The springs are critically damped, so `value` never crosses 0; the clamp below only guards the endpoints.
      const away = pane === this.current && enter !== 0 ? value * Math.sign(enter) : Math.abs(value);
      pane.style.opacity = String(Math.max(0, Math.min(1, 1 - away)));
    }, PANE_SPRING);
    if (instant) spring.set(slot, true);
    this.panes.set(pane, spring);
    return spring;
  }

  /** Removes a pane that has left the screen. */
  private drop(pane: HTMLElement): void {
    this.panes.delete(pane);
    pane.remove();
  }

  /** The height the viewport should end at: the current pane's own height. */
  private target(): number { return this.current?.offsetHeight ?? 0; }

  /** Animates the viewport from `from` to the current pane's height; settles at once under reduced motion or for a change under half a pixel. */
  private glideHeight(from: number, reduce: boolean): void {
    const to = this.target();
    if (reduce || Math.abs(to - from) < 0.5) { if (!this.moving) this.settleHeight(); return; }
    if (!this.moving) {
      this.moving = true;
      this.viewport.classList.add("is-moving");
      this.height.set(from, true);
      this.viewport.style.height = `${from}px`;
    }
    this.goal = to;
    this.height.set(to);
  }

  /** Returns the viewport to its natural height, so settled text sits on no clipped layer. */
  private settleHeight(): void {
    this.moving = false;
    this.viewport.style.height = "";
    this.viewport.classList.remove("is-moving");
  }
}
