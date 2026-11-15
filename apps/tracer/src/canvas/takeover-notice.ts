/**
 * What a signed-in page says when its connection was given to a newer tab, or cannot come back because the account
 * is full (#523, owner decision B).
 *
 * An account may keep a fixed number of live connections. When it is full, a newly opened page takes over the
 * connection of the account's tab that has been hidden the longest. That tab pauses: it does not reconnect while it
 * stays hidden (it would take yet another tab's place), and it reconnects by itself as soon as the person shows it
 * again. Most of the time the person never sees any of this.
 *
 * This module decides when the page says something about it, through one persistent toast:
 *  - while the tab is hidden, nothing (nobody would see it);
 *  - once it is shown, still paused, and not back after a short wait, "This tab is paused" with Resume, so a slow
 *    return never looks like a frozen page (a quick return shows nothing at all);
 *  - if a reconnect is refused because the account is full and no other tab is hidden, the account's limit is
 *    named at once, with Try again: the person can fix that by closing a tab;
 *  - the next welcome takes the toast down.
 *
 * The page's first connection, before the canvas exists, has its own notice in the placeholder pane
 * (startup-notice.ts); this one starts when the canvas does.
 */
import { startupProblem } from "./startup-notice";

/** How long a shown, paused tab may take to reconnect before it says it is paused. */
export const PAUSED_NOTICE_DELAY_MS = 1000;

/** What the toast says: the tab is paused for a newer one, or the account has no connection to spare. */
export type TakeoverProblem = "paused" | "limit";

/** The words and the action for each problem, in plain language (TASTE: say what happens and what to do). */
export const TAKEOVER_COPY: Readonly<Record<TakeoverProblem, { message: string; action: string }>> = {
  paused: { message: "This tab is paused while a newer tab uses its connection.", action: "Resume" },
  limit: { message: "Too many open tabs. Close one you don't need, then try again.", action: "Try again" },
};

/** What the watcher drives: put the toast up for a problem (or change it), or take it down. */
export interface TakeoverNoticeSurface {
  show(problem: TakeoverProblem): void;
  hide(): void;
}

/** Timer functions, injectable so tests can step time by hand. */
export interface TakeoverNoticeTimers {
  set(run: () => void, ms: number): number;
  clear(id: number | undefined): void;
}

/** The handle `watchTakeover` returns; the connection and the page's visibility feed it. */
export interface TakeoverWatch {
  /** The connection paused (`true`, a newer tab took it) or came back (`false`, welcomed again). */
  paused(paused: boolean): void;
  /** A reconnect closed before its welcome; `reason` is the close reason, if any (untrusted, only compared). */
  refused(reason: string | undefined): void;
  /** The page became visible or hidden. */
  visibility(): void;
  /**
   * The toast for `problem` left the screen on its own (the person pressed its action or dismissed it). A later
   * problem can show again; a paused page that is still shown waits once more before it says so.
   */
  gone(problem: TakeoverProblem): void;
  /** The connection was welcomed: whatever shows goes. */
  welcomed(): void;
  /** Stops watching and takes the toast down. */
  dispose(): void;
}

/** The page's own timers, used outside tests. */
const browserTimers: TakeoverNoticeTimers = {
  set: (run, ms) => window.setTimeout(run, ms),
  clear: (id) => window.clearTimeout(id),
};

/**
 * Starts watching. `hidden()` says whether the page is hidden right now. A timer exists only while a shown page is
 * paused and the toast is not up yet; at idle nothing runs.
 */
export function watchTakeover(
  surface: TakeoverNoticeSurface,
  hidden: () => boolean,
  delayMs = PAUSED_NOTICE_DELAY_MS,
  timers: TakeoverNoticeTimers = browserTimers,
): TakeoverWatch {
  let isPaused = false;
  let shown: TakeoverProblem | undefined;
  let timer: number | undefined;
  let disposed = false;
  const disarm = (): void => { timers.clear(timer); timer = undefined; };
  const show = (problem: TakeoverProblem): void => {
    disarm();
    if (disposed || shown === problem) return;
    shown = problem;
    surface.show(problem);
  };
  const hide = (): void => {
    disarm();
    if (shown) { shown = undefined; surface.hide(); }
  };
  /** Arms the wait for a paused page that is now shown, unless something already shows or waits. */
  const arm = (): void => {
    if (disposed || !isPaused || shown || timer !== undefined || hidden()) return;
    timer = timers.set(() => { timer = undefined; if (isPaused && !hidden()) show("paused"); }, delayMs);
  };
  return {
    paused(value) {
      if (disposed) return;
      isPaused = value;
      if (value) arm(); else hide();
    },
    refused(reason) {
      if (disposed) return;
      if (startupProblem(reason) === "limit") show("limit");
    },
    visibility() {
      if (disposed) return;
      // Going hidden leaves the toast as it is; only a wait that has not shown anything yet is dropped.
      if (hidden()) disarm(); else arm();
    },
    gone(problem) {
      if (disposed || shown !== problem) return;
      shown = undefined;
      arm();
    },
    welcomed() {
      if (disposed) return;
      isPaused = false;
      hide();
    },
    dispose() {
      if (disposed) return;
      hide();
      disposed = true;
    },
  };
}
