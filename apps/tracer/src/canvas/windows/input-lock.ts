/**
 * The input lock (the padlock, D177): all input stays inside one window. Canvas gestures and window stepping are
 * disabled, the toolbar stays on its key row, and the window shows its lock. Locking while the canvas lock is off
 * first snaps the camera to the window; unlocking restores the canvas lock to what it was before.
 */
import type { Ctx, WinRec } from "../context";

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
        win.card.setLocked(false);
        cx.core.lockToolbarRow(undefined);
        // Unlocking restores the canvas lock to what it was before.
        if (!before) cx.nav.applyCanvasLock(false);
        cx.toolbar.update();
        return;
      }
      const win = state.activeWin;
      if (!win || win.model.kind !== "terminal") return;
      const before = state.canvasLock;
      // Locked while the canvas is free: the canvas snaps to that window first.
      if (!state.canvasLock) cx.nav.focusWindow(win);
      lock = { win, before };
      win.card.setLocked(true);
      cx.core.lockToolbarRow("keys");
      win.binding?.focus();
      cx.toolbar.update();
    },
    reset() { if (lock) { lock = undefined; cx.core.lockToolbarRow(undefined); } },
  };
}
