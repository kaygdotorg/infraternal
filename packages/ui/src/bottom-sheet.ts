// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The bottom sheet (issue #304): what a popover becomes on a phone. One panel in the shared overlay material, lifted from the
 * bottom edge over a dim scrim, with a grab handle. It follows the finger while dragged down (1:1, TASTE) and closes past a short drag or a
 * flick; otherwise it springs back. A press on the scrim, Escape or the handle's drag closes it, and focus goes back to what opened it.
 *
 * It keeps clear of the home indicator (`env(safe-area-inset-bottom)`) and never grows past 70 % of the visual viewport, scrolling inside when
 * the content is longer (the on-screen keyboard shrinks the visual viewport, never the width). Motion: 240 ms strong ease-out up, 160 ms down;
 * reduced motion is a crossfade. Nothing is left transformed at rest, so text is crisp.
 */
export interface BottomSheetOptions {
  /** The positioned container the sheet is mounted in (the screen). */
  stage: HTMLElement;
  /** Accessible name of the dialog. */
  label: string;
  content: HTMLElement;
  /** What opened it; focus returns here. */
  opener: HTMLElement;
  /** Focused on a keyboard open (the sheet itself otherwise), so a keyboard user lands on the first control. */
  focus?: HTMLElement | undefined;
  source: "pointer" | "keyboard";
  onClosed(): void;
}

export interface BottomSheet {
  readonly root: HTMLElement;
  close(source: "pointer" | "keyboard"): void;
}

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;
/** A drag this far down, or a flick this fast (px per ms), closes the sheet. */
const CLOSE_DISTANCE = 72, CLOSE_SPEED = 0.6;

export function openBottomSheet(options: BottomSheetOptions): BottomSheet {
  const { stage, content, opener } = options;
  const scrim = document.createElement("div");
  scrim.className = "ui-sheet-scrim";
  const root = document.createElement("section");
  root.className = "ui-sheet ui-overlay-surface";
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-modal", "true");
  root.setAttribute("aria-label", options.label);
  root.tabIndex = -1;
  const grab = document.createElement("div");
  grab.className = "ui-sheet-grab";
  grab.innerHTML = '<span class="ui-sheet-handle" aria-hidden="true"></span>';
  root.append(grab, content);
  const fit = (): void => { root.style.maxHeight = `${Math.floor((window.visualViewport?.height ?? innerHeight) * 0.7)}px`; };
  fit();
  stage.append(scrim, root);

  if (options.source === "pointer" || reduced()) {
    const frames = reduced() ? [{ opacity: 0 }, { opacity: 1 }] : [{ transform: "translateY(100%)" }, { transform: "none" }];
    root.animate(frames, { duration: reduced() ? 160 : 240, easing: EASE });
    scrim.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, easing: "ease-out" });
  }
  (options.source === "keyboard" ? options.focus ?? root : root).focus({ preventScroll: true });

  let closed = false;
  const events = new AbortController();
  const close = (source: "pointer" | "keyboard"): void => {
    if (closed) return;
    closed = true;
    events.abort();
    const done = (): void => { root.remove(); scrim.remove(); options.onClosed(); opener.focus({ preventScroll: true }); };
    if (source === "keyboard" || reduced()) { done(); return; }
    root.style.pointerEvents = "none";
    scrim.style.pointerEvents = "none";
    // From wherever a drag left it, so a close after a drag continues the motion instead of jumping back first.
    const from = root.style.transform || "none";
    scrim.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 160, easing: "ease-out", fill: "forwards" });
    root.animate([{ transform: from }, { transform: "translateY(100%)" }], { duration: 160, easing: EASE, fill: "forwards" }).onfinish = done;
  };

  scrim.addEventListener("pointerdown", () => close("pointer"), { signal: events.signal });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") { event.stopPropagation(); close("keyboard"); } }, { capture: true, signal: events.signal });
  window.visualViewport?.addEventListener("resize", fit, { signal: events.signal });

  // A drag on the handle area: the sheet follows the finger down (a little rubber upward), and closes or springs back on release.
  let drag: { id: number; y: number; samples: Array<{ y: number; t: number }> } | undefined;
  grab.style.touchAction = "none";
  grab.addEventListener("pointerdown", (event) => { drag = { id: event.pointerId, y: event.clientY, samples: [{ y: event.clientY, t: event.timeStamp }] }; try { grab.setPointerCapture(event.pointerId); } catch { /* a pointer that is already gone (a synthetic one in a test) simply is not captured */ } }, { signal: events.signal });
  grab.addEventListener("pointermove", (event) => {
    if (!drag || event.pointerId !== drag.id) return;
    const dy = event.clientY - drag.y;
    root.style.transform = `translateY(${dy > 0 ? dy : dy * 0.2}px)`;
    drag.samples.push({ y: event.clientY, t: event.timeStamp });
    if (drag.samples.length > 5) drag.samples.shift();
  }, { signal: events.signal });
  const release = (event: PointerEvent): void => {
    if (!drag || event.pointerId !== drag.id) return;
    const d = drag;
    drag = undefined;
    const dy = event.clientY - d.y, a = d.samples[0]!, b = d.samples.at(-1)!;
    const speed = b.t > a.t ? (b.y - a.y) / (b.t - a.t) : 0;
    if (dy > CLOSE_DISTANCE || speed > CLOSE_SPEED) { close("pointer"); return; }
    const from = root.style.transform;
    root.style.transform = "";
    if (!reduced()) root.animate([{ transform: from }, { transform: "none" }], { duration: 200, easing: EASE });
  };
  grab.addEventListener("pointerup", release, { signal: events.signal });
  grab.addEventListener("pointercancel", release, { signal: events.signal });

  return { root, close };
}
