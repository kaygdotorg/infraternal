/**
 * One quiet status line: a small icon and a sentence that change state with motion
 * (owner: the line jumped from a warning to a tick with no transition).
 *
 * - The icon cell holds the idle (info), ok (tick circle) and error (alert) glyphs in one
 *   place; the active one fades and grows in while the others fade, shrink and blur, so the
 *   eye reads one morph. These are CSS transitions, so a change mid-way retargets from the
 *   current state instead of restarting.
 * - A sentence that changes whole (a different wording) crossfades: the old text leaves in an
 *   aria-hidden layer while the new one blurs in. Both take at most 160 ms.
 * - A sentence that only changes its leading number ("3 of 24 words recognised" to "4 of 24
 *   ...") keeps its words and rolls the number from what is on screen to the new value, so
 *   typing or pasting counts up smoothly and a quick second change retargets the tween.
 * - Reduced motion: every change is instant.
 *
 * Alignment (TASTE "Icon and text share one centre line"): the line is a flex row (`.ui-status-line`) and the icon cell is
 * exactly one line of the text tall (`1lh`) with the glyph centred in it, so the icon sits on the centre line of the
 * text's FIRST line at every font size and line height, and stays there when a long sentence wraps. Callers never nudge
 * the icon with margins: that is what drifted (a 3 px nudge tuned for one size was 1.5 px off at another).
 *
 * The element keeps `data-state` (idle | ok | error) for colour; callers style the rest.
 */
import { icon, ICON_ALERT, ICON_CIRCLE_CHECK, ICON_INFO } from "./icons";

export type StatusState = "idle" | "ok" | "error";
export interface StatusLine { set(state: StatusState, text: string): void }

/** The stylesheet of the status line, injected once on first use; every length is in rem and every transition reads a token from styles.css. */
const STYLE = `
.ui-status-line { display: flex; align-items: flex-start; gap: 0.5rem; min-width: 0; }
.ui-status-icons { position: relative; display: inline-grid; flex: none; height: 1lh; align-items: center; }
.ui-status-icons > .ui-icon { grid-area: 1 / 1; opacity: 0; transform: scale(0.6); filter: blur(2px);
  transition: opacity 140ms ease-out, transform 160ms var(--ease-out), filter 140ms ease-out; }
[data-state="idle"] > .ui-status-icons > .ui-status-info,
[data-state="ok"] > .ui-status-icons > .ui-status-ok,
[data-state="error"] > .ui-status-icons > .ui-status-alert { opacity: 1; transform: none; filter: none; }
.ui-status-text { position: relative; min-width: 0; transition: color 160ms ease-out; }
.ui-status-leaving { position: absolute; inset: 0 auto auto 0; width: 100%; pointer-events: none; }
@media (prefers-reduced-motion: reduce) { .ui-status-icons > .ui-icon, .ui-status-text { transition: none; } }
`;

const MOVE = 160;
let styled = false;

export function statusLine(root: HTMLElement): StatusLine {
  if (!styled) { styled = true; const style = document.createElement("style"); style.textContent = STYLE; document.head.append(style); }
  root.classList.add("ui-status-line");
  root.innerHTML = `<span class="ui-status-icons">${icon(ICON_INFO, "ui-status-info")}${icon(ICON_CIRCLE_CHECK, "ui-status-ok")}${icon(ICON_ALERT, "ui-status-alert")}</span><span class="ui-status-text"><span class="ui-status-num"></span><span class="ui-status-rest"></span></span>`;
  const box = root.querySelector<HTMLElement>(".ui-status-text")!;
  const num = box.querySelector<HTMLElement>(".ui-status-num")!;
  const rest = box.querySelector<HTMLElement>(".ui-status-rest")!;
  let shown = "";          // the sentence the line is currently heading for
  let frame = 0, value = 0; // the rolling number: displayed value, may be fractional mid-tween

  const split = (text: string): [string, string] => { const m = /^(\d+)(.*)$/s.exec(text); return m ? [m[1]!, m[2]!] : ["", text]; };
  const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

  function roll(to: number): void {
    cancelAnimationFrame(frame);
    const from = value, start = performance.now();
    const step = (now: number): void => {
      const t = Math.min(1, (now - start) / MOVE);
      value = from + (to - from) * (1 - (1 - t) ** 3);
      num.textContent = String(Math.round(value));
      if (t < 1) frame = requestAnimationFrame(step); else { value = to; num.textContent = String(to); }
    };
    frame = requestAnimationFrame(step);
  }

  return {
    set(state, text) {
      root.dataset.state = state;
      if (text === shown) return;
      const [nextNum, nextRest] = split(text);
      const [, prevRest] = split(shown);
      const first = shown === "";
      shown = text;
      if (first || reduced()) {
        cancelAnimationFrame(frame);
        num.textContent = nextNum; rest.textContent = nextRest; value = Number(nextNum || 0);
        return;
      }
      if (nextNum !== "" && nextRest === prevRest) { roll(Number(nextNum)); return; }
      // A different sentence: the old one leaves in its own layer while the new one blurs in.
      cancelAnimationFrame(frame);
      const leaving = document.createElement("span");
      leaving.className = "ui-status-leaving";
      leaving.setAttribute("aria-hidden", "true");
      leaving.textContent = `${num.textContent}${rest.textContent}`;
      box.append(leaving);
      const out = leaving.animate([{ opacity: 1, filter: "blur(0)" }, { opacity: 0, filter: "blur(3px)" }], { duration: 120, easing: "ease-out", fill: "forwards" });
      out.onfinish = () => leaving.remove();
      num.textContent = nextNum; rest.textContent = nextRest; value = Number(nextNum || 0);
      for (const part of [num, rest]) part.animate([{ opacity: 0, filter: "blur(3px)" }, { opacity: 1, filter: "blur(0)" }], { duration: MOVE, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
    },
  };
}
