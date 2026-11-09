/**
 * When the canvas shows "Not saved — keep this tab open" (D312, amended by D358, #395).
 *
 * Every layout edit waits briefly for the server's receipt, so a notice shown at once would flash on almost every move
 * or resize. The notice appears only when an edit is still unsaved after about a second, which means real trouble (a
 * slow or lost connection), and then stays until every waiting edit is saved.
 *
 * Invariants:
 *  - A timer exists only while something waits and the notice is not yet up: at idle, and while it shows, nothing runs.
 *  - The clock starts with the first waiting edit, not the latest: a steady stream of edits that never empties the
 *    queue still shows the notice after a second.
 *  - When the queue empties, the timer is cleared and the notice hidden; the next wait starts from zero.
 */

/** How long an edit may wait for its receipt before the notice shows (owner: "Wait ~1 s before showing", D358). */
export const PENDING_NOTICE_DELAY_MS = 1000;

/** What the watcher drives: put the notice up, or take it down. */
export interface PendingNoticeSurface {
  show(): void;
  hide(): void;
}

/** Timer functions, injectable so tests can step time by hand. */
export interface PendingNoticeTimers {
  set(run: () => void, ms: number): number;
  clear(id: number | undefined): void;
}

/** The handle `watchPendingNotice` returns. */
export interface PendingNoticeWatch {
  /** Call whenever the store's pending state may have changed; cheap and idempotent. */
  update(): void;
  /** Disarms the timer and hides the notice; later `update` calls do nothing. */
  dispose(): void;
}

/** The page's own timers, used outside tests. */
const browserTimers: PendingNoticeTimers = {
  set: (run, ms) => window.setTimeout(run, ms),
  clear: (id) => window.clearTimeout(id),
};

/**
 * Shows `surface` once `pending()` has stayed true for `delayMs`, and hides it as soon as `pending()` is false.
 * Call `update()` from the store's pending-change listener.
 */
export function watchPendingNotice(
  pending: () => boolean,
  surface: PendingNoticeSurface,
  delayMs = PENDING_NOTICE_DELAY_MS,
  timers: PendingNoticeTimers = browserTimers,
): PendingNoticeWatch {
  let timer: number | undefined;
  let shown = false;
  let disposed = false;
  const disarm = (): void => { timers.clear(timer); timer = undefined; };
  return {
    update() {
      if (disposed) return;
      if (!pending()) {
        disarm();
        if (shown) { shown = false; surface.hide(); }
        return;
      }
      if (shown || timer !== undefined) return;
      timer = timers.set(() => {
        timer = undefined;
        if (disposed || !pending()) return;
        shown = true;
        surface.show();
      }, delayMs);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      disarm();
      if (shown) { shown = false; surface.hide(); }
    },
  };
}
