/**
 * The input lock (the padlock, D177): all input stays inside one window. Canvas gestures and window stepping are
 * disabled, the toolbar stays on its key row, and the window shows its lock. Locking while the canvas lock is off
 * first snaps the camera to the window; unlocking restores the canvas lock to what it was before.
 */
import type { Ctx, WinRec } from "../context";
import { isInteractive } from "../views/body";

export interface InputLock {
  /** The locked window, while there is one. */
  readonly state: { win: WinRec; before: boolean } | undefined;
  toggle(): void;
  /** Drops the lock without restoring anything (the canvas is being rebuilt). */
  reset(): void;
}

export function createInputLock(cx: Ctx): InputLock {
  const { state } = cx;
  let lock: { win: WinRec; before: boolean } | undefined;
  return {
    get state() { return lock; },
    toggle() {
      if (lock) {
        const { win, before } = lock;
        lock = undefined;
        cx.viewport.removeAttribute("data-input-lock");
        win.card.setLocked(false);
        cx.core.lockToolbarRow(undefined);
        // Unlocking restores the canvas lock to what it was before.
        if (!before) cx.nav.applyCanvasLock(false);
        cx.toolbar.update();
        return;
      }
      const win = state.activeWin;
      if (!win || !isInteractive(win)) return;
      const before = state.canvasLock;
      // Locked while the canvas is free: the canvas snaps to that window first.
      if (!state.canvasLock) cx.nav.focusWindow(win);
      lock = { win, before };
      cx.viewport.setAttribute("data-input-lock", "");
      win.card.setLocked(true);
      // The key row sends to a terminal; an app window takes the real keyboard (or none, on a phone).
      if (win.model.kind === "terminal") cx.core.lockToolbarRow("keys");
      // A touch screen's keyboard opens when an input is focused, and a lock button must not open it: the person
      // taps the terminal for that. With a hardware keyboard the lock takes the focus so keys flow at once.
      if (!matchMedia("(pointer: coarse)").matches) win.binding?.focus();
      cx.toolbar.update();
    },
    reset() { if (lock) { lock = undefined; cx.viewport.removeAttribute("data-input-lock"); cx.core.lockToolbarRow(undefined); } },
  };
}
