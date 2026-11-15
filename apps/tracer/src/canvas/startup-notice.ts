/**
 * What the signed-in page says while its first connection cannot be made (#523).
 *
 * The canvas mounts only once the server has sent the account's saved layout, and that needs a welcomed connection.
 * Until then the page shows the core screen's placeholder pane. When the connection never comes (the server refuses
 * it, or cannot be reached), that placeholder used to stay blank and silent. On QA1, a phone that kept every old tab
 * open took up all of the account's connections, and every fresh load sat there with no toolbar and no words.
 *
 * This module puts a plain notice in the placeholder pane instead:
 *  - the account's connection limit is named at once, because the person can fix it (close a tab they don't need);
 *  - any other trouble shows only after a short wait, so an ordinary load or a brief blip never flashes it;
 *  - "Try again" asks the connection to retry now; the connection also keeps retrying by itself;
 *  - the first welcome ends the startup: the notice goes, and later closes belong to the canvas's own states.
 */
import { CONNECTION_LIMIT_REASON } from "../close-reasons";

/** The reason the server sends when the account already holds all its connections; it lives with the other reasons. */
export { CONNECTION_LIMIT_REASON };

/** How long a page waits for its first welcome before it says it cannot reach the server. */
export const STARTUP_NOTICE_DELAY_MS = 4000;

/** Why the page is not connected yet: the account's limit, or anything else (refused, unreachable, no answer). */
export type StartupProblem = "limit" | "unreachable";

/** The words for each problem: a short title, one line on what happens next, in the empty-view placeholder's style. */
export const STARTUP_COPY: Readonly<Record<StartupProblem, { title: string; hint: string }>> = {
  limit: {
    title: "Too many open tabs",
    hint: "This account is open in too many browser tabs. Close the ones you don't need and this page connects by itself.",
  },
  unreachable: {
    title: "Can't reach the server",
    hint: "This page keeps trying to connect by itself.",
  },
};

/** What the watcher drives: put the notice up for a problem (or change it), or take it down. */
export interface StartupNoticeSurface {
  show(problem: StartupProblem): void;
  hide(): void;
}

/** Timer functions, injectable so tests can step time by hand. */
export interface StartupNoticeTimers {
  set(run: () => void, ms: number): number;
  clear(id: number | undefined): void;
}

/** The handle `watchStartup` returns; the connection feeds it. */
export interface StartupWatch {
  /** A socket closed before the server welcomed it; `reason` is the close reason, if any (untrusted, only compared). */
  closed(reason: string | undefined): void;
  /** The server welcomed a socket: startup is over, the notice goes and later calls do nothing. */
  welcomed(): void;
  /** Ends the watch without a welcome (the canvas went away); hides the notice. */
  dispose(): void;
}

/** The page's own timers, used outside tests. */
const browserTimers: StartupNoticeTimers = {
  set: (run, ms) => window.setTimeout(run, ms),
  clear: (id) => window.clearTimeout(id),
};

/** Which problem a pre-welcome close reports. Only an exact match names the limit; anything else is "unreachable". */
export function startupProblem(reason: string | undefined): StartupProblem {
  return (reason ?? "").trim() === CONNECTION_LIMIT_REASON ? "limit" : "unreachable";
}

/**
 * Starts watching a page's first connection. The limit shows at once; other trouble shows after `delayMs` without a
 * welcome, worded by the latest close. Nothing runs once the page is welcomed or the watch is disposed.
 */
export function watchStartup(
  surface: StartupNoticeSurface,
  delayMs = STARTUP_NOTICE_DELAY_MS,
  timers: StartupNoticeTimers = browserTimers,
): StartupWatch {
  let problem: StartupProblem = "unreachable";
  let shown: StartupProblem | undefined;
  let done = false;
  let timer: number | undefined = timers.set(() => { timer = undefined; show(); }, delayMs);
  const disarm = (): void => { timers.clear(timer); timer = undefined; };
  const show = (): void => {
    if (done || shown === problem) return;
    shown = problem;
    surface.show(problem);
  };
  const finish = (): void => {
    if (done) return;
    done = true;
    disarm();
    if (shown) { shown = undefined; surface.hide(); }
  };
  return {
    closed(reason) {
      if (done) return;
      problem = startupProblem(reason);
      // The limit is the person's to fix, so it is named at once; other closes keep the wait unless already showing.
      if (problem === "limit" || shown) { disarm(); show(); }
    },
    welcomed: finish,
    dispose: finish,
  };
}

/**
 * The notice itself, inside the placeholder pane: the empty view's title, hint and pill (one look for "nothing here
 * yet, and why"), with "Try again" calling `retry`. Announced politely to screen readers.
 */
export function mountStartupNotice(parent: HTMLElement, retry: () => void): StartupNoticeSurface {
  let box: HTMLElement | undefined;
  return {
    show(problem) {
      if (!box) {
        // Plain DOM calls, not canvas/dom.ts: that module reads media queries on load, which keeps this one testable.
        box = document.createElement("div");
        box.className = "cl-empty startup-notice";
        box.setAttribute("role", "status");
        box.innerHTML = `<p class="cl-empty-title"></p><p class="cl-empty-hint"></p>`;
        const button = document.createElement("button");
        button.className = "ui-pill cl-empty-add";
        button.type = "button";
        button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 12a7 7 0 1 1-2.05-4.95"/><path d="M19 4v4h-4"/></svg><span>Try again</span>`;
        button.addEventListener("click", retry);
        box.append(button);
        parent.append(box);
      }
      box.dataset.problem = problem;
      box.querySelector(".cl-empty-title")!.textContent = STARTUP_COPY[problem].title;
      box.querySelector(".cl-empty-hint")!.textContent = STARTUP_COPY[problem].hint;
    },
    hide() {
      box?.remove();
      box = undefined;
    },
  };
}
