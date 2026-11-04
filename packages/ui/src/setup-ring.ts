/**
 * The setup ring (D255, TASTE "Progress lives where the thing is"): a small circle split into equal arcs, one per
 * remaining stage of a background job. It sits in the slot of a window's machine mark (`.ui-window-mark`) or flies
 * toward it, and has exactly the size of that slot, so the pill never changes width while a job runs.
 *
 * The life of a ring, all driven by `setStages` and `complete`:
 *   - each arc is pending (a faint track), running (the arc pulses), done (the arc is filled) or failed (the arc turns
 *     to the danger colour; a failure never shows a tick);
 *   - when every arc is done the circle morphs into a tick (about 150 ms), holds, and crossfades into the mark that
 *     was underneath (the machine's system icon), after which the ring takes itself out of the DOM.
 *
 * Motion is opacity and transform only, written as CSS transitions on `data-*` attributes (styles.css), so every
 * change is interruptible and costs no JavaScript per frame. Reduced motion: no pulse and no scale; fills and the
 * tick change with a short opacity fade. Nothing keeps a transform or `will-change` at rest, so text stays crisp.
 *
 * API:
 *   const ring = mountSetupRing(slot, { segments: 4, label: "Setting up demo" });  // inside `.ui-window-mark`
 *   ring.setStages(["done", "running", "pending", "pending"]);
 *   ring.complete();           // → Promise<void> that resolves once the system icon is back and the ring is gone
 *   const loose = createSetupRing({ segments: 4 });   // not mounted: a flight carries it from one place to another
 *   ring.show(false) / ring.show(true)                 // hide the ring while a flight carries a copy of it
 */
import { TICK_PATH } from "./tick";

/** The state of one arc of the ring (see the module comment). */
export type RingStageState = "pending" | "running" | "done" | "failed";

/** Options for {@link createSetupRing} and {@link mountSetupRing}. */
export interface SetupRingOptions {
  /** How many arcs the circle is split into (default 4). */
  segments?: number;
  /** Spoken to assistive technology as the ring changes. */
  label?: string;
}

/** The ring's controller; `root` is its element. */
export interface SetupRing {
  readonly root: HTMLElement;
  /** Sets every arc; extra states are ignored, missing ones are pending. */
  setStages(states: readonly RingStageState[]): void;
  /** Hides or reveals the ring in place (the pill's copy waits while a flying copy travels). */
  show(visible: boolean, instant?: boolean): void;
  /** Circle → tick → hold → system icon. Resolves when the ring is gone. Safe to call twice. */
  complete(options?: { hold?: number }): Promise<void>;
  /** Removes the ring at once. */
  dispose(): void;
}

/** The SVG namespace for elements the ring creates. */
const SVG_NS = "http://www.w3.org/2000/svg";
/** Radius of the circle on the 24 px grid, and the gap between arcs in degrees (round caps add their own length). */
const RADIUS = 8, GAP_DEG = 26;
/** Whether the user asks for reduced motion, read at each use. */
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** An arc from `from` to `to` degrees, clockwise from twelve o'clock. */
function arc(from: number, to: number): string {
  const point = (deg: number): string => {
    const rad = ((deg - 90) * Math.PI) / 180;
    return `${(12 + RADIUS * Math.cos(rad)).toFixed(2)} ${(12 + RADIUS * Math.sin(rad)).toFixed(2)}`;
  };
  return `M${point(from)}A${RADIUS} ${RADIUS} 0 ${to - from > 180 ? 1 : 0} 1 ${point(to)}`;
}

/** Builds a ring that is not in the document yet. */
export function createSetupRing(options: SetupRingOptions = {}): SetupRing {
  const count = Math.max(2, options.segments ?? 4);
  const root = document.createElement("span");
  root.className = "ui-setup-ring";
  root.dataset.phase = "ring";

  const circle = document.createElementNS(SVG_NS, "svg");
  circle.setAttribute("viewBox", "0 0 24 24");
  circle.setAttribute("class", "ui-setup-arcs");
  circle.setAttribute("aria-hidden", "true");
  const span = 360 / count;
  // Each arc is centred on its slice; the gap is split on both sides so the circle stays symmetric. The tracks are
  // drawn first and the fills above them, so a fill covers its track exactly.
  const draw = (kind: "track" | "fill"): SVGPathElement[] => Array.from({ length: count }, (_, i) => {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", arc(i * span + GAP_DEG / 2, (i + 1) * span - GAP_DEG / 2));
    path.setAttribute("class", `ui-setup-${kind}`);
    if (kind === "fill") path.dataset.state = "pending";
    return path;
  });
  const fills = draw("fill");
  circle.append(...draw("track"), ...fills);

  const check = document.createElementNS(SVG_NS, "svg");
  check.setAttribute("viewBox", "0 0 24 24");
  check.setAttribute("class", "ui-setup-check");
  check.setAttribute("aria-hidden", "true");
  const stroke = document.createElementNS(SVG_NS, "path");
  stroke.setAttribute("d", TICK_PATH);
  stroke.setAttribute("pathLength", "1");
  check.append(stroke);

  const status = document.createElement("span");
  status.className = "visually-hidden";
  status.setAttribute("role", "status");
  root.append(circle, check, status);

  let finished: Promise<void> | undefined;
  let gone = false;
  let timers: number[] = [];
  const later = (ms: number, fn: () => void): void => { timers.push(window.setTimeout(fn, ms)); };
  const slot = (): HTMLElement | null => root.parentElement;

  const ring: SetupRing = {
    root,
    setStages(states) {
      fills.forEach((fill, i) => { fill.dataset.state = states[i] ?? "pending"; });
      const failed = states.findIndex((s) => s === "failed");
      const done = states.filter((s) => s === "done").length;
      root.dataset.failed = failed >= 0 ? "true" : "false";
      // Spoken once per change, as a short sentence; the visual is for sighted users.
      status.textContent = failed >= 0 ? `${options.label ?? "Setup"}: step ${failed + 1} of ${count} failed` : `${options.label ?? "Setup"}: ${done} of ${count} steps done`;
    },
    show(visible, instant = false) {
      if (instant) root.dataset.instant = "";
      root.dataset.hidden = visible ? "false" : "true";
      slot()?.setAttribute("data-setup", visible ? root.dataset.phase! : "hidden");
      if (instant) requestAnimationFrame(() => { delete root.dataset.instant; });
    },
    complete({ hold = 600 } = {}) {
      if (finished) return finished;
      finished = new Promise<void>((resolve) => {
        const host = slot();
        // Circle → tick. The circle's arcs close into one colour, then the tick draws on (CSS, 150 ms).
        root.dataset.phase = "tick";
        host?.setAttribute("data-setup", "tick");
        later(150 + hold, () => {
          // Tick → system icon: a crossfade; the ring is removed once the fade has played.
          root.dataset.phase = "rest";
          host?.setAttribute("data-setup", "rest");
          later(reduced() ? 160 : 240, () => { ring.dispose(); resolve(); });
        });
      });
      return finished;
    },
    dispose() {
      if (gone) return;
      gone = true;
      for (const t of timers) window.clearTimeout(t);
      timers = [];
      slot()?.removeAttribute("data-setup");
      root.remove();
    },
  };
  ring.setStages([]);
  return ring;
}

/**
 * Mounts a ring into a window's mark slot, above the system icon that is already there. While the ring shows, the
 * slot carries `data-setup`, which hides the icon underneath; the ring gives it back when it is done.
 */
export function mountSetupRing(slot: HTMLElement, options: SetupRingOptions = {}): SetupRing {
  const ring = createSetupRing(options);
  slot.append(ring.root);
  ring.show(true, true);
  return ring;
}
