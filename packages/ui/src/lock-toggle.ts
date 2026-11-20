/**
 * The window lock (D160): a small padlock at the top-middle of a window card that, once
 * locked, keeps all keyboard and mouse input in that window. One shared component; the
 * persistent state lives on the window card (`data-locked`, `WindowCard.locked`), and the
 * canvas decides what locking means.
 *
 * Look and motion:
 * - At rest it is invisible. A mouse within 64 px of the window's top edge fades it in at
 *   35 % opacity (touch has no frame lock; the toolbar and the palette lock there). Locked, it stays
 *   at full strength with an accent tint, and the window's hairline gets stronger (styles.css).
 * - The shackle is one spring value `t` (0 open, 1 shut) critically damped, about 260 ms:
 *   it starts lifted and tilted, drops and snaps shut. Unlocking plays it in reverse from
 *   wherever it is (interruptible, velocity kept). Reduced motion: no shackle travel, a short
 *   crossfade of the whole icon instead.
 * - Its position is pure CSS (`left: 50%` of the card): nothing measures or nudges it, so hover, focus, resize,
 *   fonts and a long title cannot move it. The title pill yields instead (max-width in styles.css).
 * - It is the glyph itself, centred on the window's top frame line: the shackle rises above the line,
 *   the body hangs below it (styles.css). The button is a 44 px invisible hit area.
 * - The warm tooltip is short and literal: "Lock input" / "Unlock input".
 *
 *   const lock = createLockToggle({ onToggle: (next, source) => … });
 *   card.append(lock.root); lock.setLocked(true);
 */
import { Spring } from "./spring";
import { EASE_OUT } from "./motion";

/** What caused a toggle: a pointer click or a keyboard activation (a click with `detail` 0). */
export type LockSource = "pointer" | "keyboard";

/** Options for {@link createLockToggle}. `onToggle` is told the state being asked for; it must call `setLocked` itself to accept it. */
export interface LockToggleOptions {
  onToggle(next: boolean, source: LockSource): void;
}

/** The padlock control. `root` is the button to place in a window card; `locked` is the current state. `dispose()` removes the button and its listener. */
export interface LockToggle {
  readonly root: HTMLButtonElement;
  readonly locked: boolean;
  /** `instant` skips the animation (keyboard and programmatic changes). */
  setLocked(locked: boolean, instant?: boolean): void;
  /** A tiny pulse that says "the lock is what holds the input", without any text. */
  nudge(): void;
  dispose(): void;
}

/** The padlock's body, as SVG markup. */
const BODY = '<rect class="ui-lock-body" x="5" y="11" width="14" height="9.5" rx="2.5"/>';
/** The padlock's shackle (the U-shaped bar), as SVG markup. */
const SHACKLE = '<path class="ui-lock-shackle" d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>';
// The shackle pivots about its left foot, like a real padlock opening.
const PIVOT_X = 8.5, PIVOT_Y = 11;
/** How far (px) the open shackle is raised, and how far (degrees) it is tilted. */
const LIFT = 3, TILT = 22;

/** Short and literal; the chord that leaves the lock is in the shortcuts view and the palette. */
export const lockLabel = (locked: boolean): string => locked
  ? "Unlock input"
  : "Lock input";

/**
 * Builds the padlock button. It starts open and does not change by itself when clicked: `options.onToggle(next, source)` is
 * called and the owner calls `setLocked(next)` if the change is allowed. The button sets `aria-pressed`, `data-state`
 * and the tooltip text (see {@link lockLabel}).
 */
export function createLockToggle(options: LockToggleOptions): LockToggle {
  const root = document.createElement("button");
  root.type = "button";
  root.className = "ui-window-lock";
  root.setAttribute("aria-pressed", "false");
  root.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${SHACKLE}${BODY}</svg>`;
  const icon = root.querySelector<SVGElement>("svg")!;
  const shackle = root.querySelector<SVGPathElement>(".ui-lock-shackle")!;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");

  let locked = false;
  const draw = (t: number): void => {
    // t 0 = open (lifted, tilted), 1 = shut. t never passes 1, so the shackle stops exactly shut.
    shackle.style.transform = `translateY(${-LIFT * (1 - t)}px) rotate(${-TILT * (1 - t)}deg)`;
  };
  const spring = new Spring(0, draw, { visualDuration: 0.2 });
  shackle.style.transformOrigin = `${PIVOT_X}px ${PIVOT_Y}px`;

  const label = (): void => {
    const text = lockLabel(locked);
    root.dataset.tip = text;
    root.setAttribute("aria-label", text);
  };
  label();

  const setLocked = (next: boolean, instant = false): void => {
    if (next === locked) return;
    locked = next;
    root.dataset.state = locked ? "locked" : "open";
    root.setAttribute("aria-pressed", String(locked));
    label();
    if (instant || reduced.matches) {
      spring.set(locked ? 1 : 0, true);
      if (!instant) icon.animate([{ opacity: 0.2 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
    } else {
      spring.set(locked ? 1 : 0);
    }
  };

  const onClick = (event: MouseEvent): void => options.onToggle(!locked, event.detail === 0 ? "keyboard" : "pointer");
  root.addEventListener("click", onClick);

  return {
    root,
    /** The current state. */
    get locked() { return locked; },
    setLocked,
    nudge() {
      if (reduced.matches) return;
      root.animate([{ transform: "scale(1)" }, { transform: "scale(1.18)" }, { transform: "scale(1)" }], { duration: 220, easing: EASE_OUT });
    },
    dispose() { root.removeEventListener("click", onClick); root.remove(); },
  };
}

// ---- reveal: pointer proximity on desktop, header taps on touch ------------------------------
// One document listener serves every window. A frame at most reads each tracked window's
// top edge, and only a change of state touches the DOM.
/** How far (px) below a window's top edge the mouse still counts as "near". The check also allows 16 px above the edge. */
const NEAR = 64;
/** Windows whose lock is revealed by pointer proximity. */
const tracked = new Set<{ root: HTMLElement; lock: LockToggle }>();
/** Whether the shared document listeners are installed. They are never removed. */
let listening = false;
/** The pending animation frame for {@link sweep}, or 0. */
let frame = 0;
/** The last mouse position, or `undefined` after the pointer left the document. */
let pointer: { x: number; y: number } | undefined;

/** Marks each tracked window `data-lock-near` while the mouse is near its top edge; one write per change of state. */
const sweep = (): void => {
  frame = 0;
  for (const entry of tracked) {
    const box = entry.root.getBoundingClientRect();
    const near = !!pointer && pointer.x >= box.left && pointer.x <= box.right && pointer.y >= box.top - 16 && pointer.y <= box.top + NEAR;
    if (near !== entry.root.hasAttribute("data-lock-near")) {
      // The pointer moved it, so the reveal keeps its fade even if a key made the window's last change instant (#427).
      entry.root.setAttribute("data-motion", "animate");
      entry.root.toggleAttribute("data-lock-near", near);
    }
  }
};

/** Starts revealing `lock` for `root`; returns a disposer. */
export function trackLockReveal(root: HTMLElement, lock: LockToggle): () => void {
  const entry = { root, lock };
  tracked.add(entry);
  if (!listening) {
    listening = true;
    document.addEventListener("pointermove", (event) => {
      if (event.pointerType !== "mouse") return;
      pointer = { x: event.clientX, y: event.clientY };
      if (!frame) frame = requestAnimationFrame(sweep);
    }, { passive: true });
    document.addEventListener("pointerleave", () => { pointer = undefined; if (!frame) frame = requestAnimationFrame(sweep); });
  }
  return () => { tracked.delete(entry); };
}
