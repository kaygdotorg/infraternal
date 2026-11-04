/**
 * The body of a logs window, loaded on demand with the first one (D188): it behaves like `tail -f`. The window
 * shows a backlog that fills it, new lines are appended as they arrive, and the view stays pinned to the newest
 * line unless the person scrolled up to read; then a small
 * "Jump to latest" button appears, and a press (or scrolling back to the end) pins it again. A line is
 * `time  source  message`; a message that starts with `WARN` or `ERROR` is tinted.
 *
 * Appending never animates (results do not animate) and costs one element per line; the list is capped so a window
 * left open for days stays small.
 */
import { el } from "../dom";

/** Most lines a logs window keeps. Older lines are dropped as new ones arrive. */
const CAP = 500;
/** Within this many pixels of the end counts as "at the end" (sub-pixel scroll positions, rounding). */
const PIN_SLACK = 8;
/** Icon markup for the "Jump to latest" button. */
const ARROW_DOWN = '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M12 5v14M6 13l6 6 6-6"/></svg>';

/** Builds one log line from `time  source  message` (two spaces apart). A message starting with WARN or ERROR is tinted. */
function lineEl(line: string): HTMLElement {
  const [time, src, ...rest] = line.split("  ");
  const msg = rest.join("  ");
  const row = el("span", "cl-log-line");
  row.append(el("span", "cl-log-time", time ?? ""), "  ", el("span", "cl-log-src", src ?? ""), "  ");
  const level = /^(WARN|ERROR)\b/.exec(msg)?.[1];
  const text = el("span", level ? `cl-log-${level.toLowerCase()}` : "", msg);
  row.append(text, "\n");
  return row;
}

/** A mounted log view. `push` appends a line (the view stays pinned to the end unless the person scrolled up). */
export interface LogBody {
  /** The scrolling element. */
  scroller: HTMLElement;
  push(line: string): void;
}

/** Fills `body` with a log view of `lines` (oldest first), pinned to the end. */
export function mountLogBody(body: HTMLElement, lines: readonly string[]): LogBody {
  const pre = el("pre", "canvas-preview cl-preview cl-logs");
  pre.setAttribute("role", "log");
  const jump = el("button", "ui-pill ui-pill-icon cl-log-jump");
  jump.type = "button";
  jump.setAttribute("aria-label", "Jump to latest");
  jump.dataset.tip = "Jump to latest";
  jump.hidden = true;
  jump.innerHTML = ARROW_DOWN;
  let pinned = true;
  const atEnd = (): boolean => pre.scrollHeight - pre.scrollTop - pre.clientHeight <= PIN_SLACK;
  const toEnd = (): void => { pre.scrollTop = pre.scrollHeight; };
  const setPinned = (on: boolean): void => { pinned = on; jump.hidden = on; };
  pre.addEventListener("scroll", () => setPinned(atEnd()), { passive: true });
  jump.addEventListener("click", () => { toEnd(); setPinned(true); });
  const frag = document.createDocumentFragment();
  for (const l of lines.slice(-CAP)) frag.append(lineEl(l));
  pre.append(frag);
  body.append(pre, jump);
  toEnd();
  return {
    scroller: pre,
    push(line) {
      const wasPinned = pinned;
      pre.append(lineEl(line));
      while (pre.childElementCount > CAP) pre.firstElementChild!.remove();
      if (wasPinned) toEnd();
    },
  };
}
