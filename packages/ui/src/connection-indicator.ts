/**
 * The connection indicator: one small icon (16 px) that shows the state of a terminal's link,
 * with its own motion per state and a warm sentence in the shared tooltip. It replaces every
 * bordered status text line: nothing here ever draws a text box.
 *
 * States and what they look like:
 * - connecting / reconnecting: an arc turning around a faint ring (a turn every 900 ms).
 * - connected: a calm green dot with a still halo. Nothing moves while the link is healthy, so
 *   an idle terminal schedules no animation frames [81].
 * - slow: an amber dot whose halo breathes outward three times when the link turns slow, then rests as a still amber
 *   dot (a looping animation would keep the compositor drawing frames, and re-blurring the glass under it, for as long
 *   as the link is slow; an idle page must do no work).
 * - resumed: a tick pops in over the dot and settles back to "connected" by itself.
 * - approximate: a screen with its lower half filled (the picture was rebuilt, not replayed);
 *   it settles back to "connected" after a few seconds, longer than a tick so it is read.
 * - offline: a slashed hollow ring. Still and quiet; the sentence says why.
 *
 * Motion rules: only `transform` and `opacity` ever animate (compositor-only). Every glyph is
 * its own layer and the shown one is chosen with CSS transitions, so a state change in the
 * middle of another one retargets from where the layers are instead of restarting. Looping
 * animations are paused, never removed, when their glyph hides, so they never jump. With
 * reduced motion the glyphs only cross-fade and nothing loops.
 *
 * Slow is derived: `setRoundTrip` flips "connected" to "slow" above `slowAtMs` and back below
 * `slowAtMs - 60` (hysteresis, so a link hovering at the threshold does not flicker).
 *
 * Accessibility: the sentence is the tooltip, the element's accessible name, and, for the one
 * instance created with `announce`, a polite live region. Hover and keyboard use the shared
 * tooltip; on touch a tap peeks the tooltip (and is swallowed there, since a 16 px mark is
 * never the target of another action), and the shared long press works as everywhere.
 *
 *   const ind = createConnectionIndicator({ announce: true });
 *   host.append(ind.root);
 *   ind.set("reconnecting");      ind.setRoundTrip(182);
 *   ind.set("offline", "Your passkey session ended.");   // the reason is a plain sentence of its own, shown after "Offline."
 */
import { peekTip, refreshTip } from "./tooltip";

export type ConnectionIndicatorState = "connecting" | "connected" | "slow" | "reconnecting" | "resumed" | "approximate" | "offline";

export interface ConnectionIndicatorOptions {
  /** Owns the polite live region. Exactly one indicator per screen should announce. */
  announce?: boolean;
  /** Round trip (ms) at or above which a healthy link reads as slow. Default 300. */
  slowAtMs?: number;
}

export interface ConnectionIndicator {
  readonly root: HTMLElement;
  /** The state being shown (after any slow derivation or settling). */
  readonly state: ConnectionIndicatorState;
  /** Sets the link state; `detail` is a reason shown after "Offline —". */
  set(state: ConnectionIndicatorState, detail?: string, queued?: number): void;
  setRoundTrip(ms: number | undefined): void;
  dispose(): void;
}

/** Three breaths of 1.7 s (see styles.css). */
const BREATH_MS = 5100;
const SETTLE_MS: Partial<Record<ConnectionIndicatorState, number>> = { resumed: 1800, approximate: 3200 };

const GLYPHS = `
<span class="ui-conn-g ui-conn-g-connected"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" class="halo"/><circle cx="8" cy="8" r="3.2" class="core"/></svg></span>
<span class="ui-conn-g ui-conn-g-slow"><span class="ui-conn-pulse"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="3.2" class="ring"/></svg></span><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" class="halo"/><circle cx="8" cy="8" r="3.2" class="core"/></svg></span>
<span class="ui-conn-g ui-conn-g-reconnecting"><span class="ui-conn-spin"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" class="track"/><circle cx="8" cy="8" r="5.5" class="arc" pathLength="100"/></svg></span></span>
<span class="ui-conn-g ui-conn-g-resumed"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.2" class="disc"/><path d="m5 8.4 2.2 2.2 3.9-4.6" class="tick"/></svg></span>
<span class="ui-conn-g ui-conn-g-approximate"><svg viewBox="0 0 16 16"><rect x="2.4" y="3" width="11.2" height="8" rx="2" class="frame"/><path d="M3.6 7.6h8.8v1.6a1.3 1.3 0 0 1-1.3 1.3H4.9a1.3 1.3 0 0 1-1.3-1.3z" class="fill"/><path d="M6 13.4h4" class="foot"/></svg></span>
<span class="ui-conn-g ui-conn-g-offline"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="4.6" class="ring"/><path d="m4.4 11.6 7.2-7.2" class="slash"/></svg></span>
<span class="ui-conn-q" aria-hidden="true"><svg viewBox="0 0 16 16"><circle cx="5" cy="11" r="3"/><path d="m7.2 8.8 5.8-5.8M11.2 4.8l1.6 1.6M9.4 6.6l1.2 1.2"/></svg></span>`;

/** The sentence for a state: plain, warm, and honest about what was kept. */
export function connectionSentence(state: ConnectionIndicatorState, rtt?: number, detail?: string, queued = 0): string {
  const keys = queued === 1 ? "1 key you typed is kept" : `${queued} keys you typed are kept`;
  const ms = rtt === undefined ? "" : ` · ${Math.round(rtt)} ms`;
  switch (state) {
    case "connecting": return "Connecting to this machine…";
    case "connected": return `Connected${ms}`;
    case "slow": return `Slow connection${ms}. Typing may feel a little delayed.`;
    case "reconnecting": return queued > 0 ? `Connection lost — resuming. ${keys} and will be sent.` : "Connection lost — resuming without losing anything";
    case "resumed": return "Back online. You are exactly where you left off.";
    case "approximate": return "Back online. The screen was rebuilt from the latest state; a little scrollback may be approximate.";
    case "offline": return queued > 0 ? `Offline. ${keys} and will be sent when it is back.` : detail ? `Offline. ${detail}` : "Offline. This machine can't be reached right now.";
  }
}


export function createConnectionIndicator(options: ConnectionIndicatorOptions = {}): ConnectionIndicator {
  const slowAt = options.slowAtMs ?? 300;
  const root = document.createElement("span");
  root.className = "ui-conn";
  root.setAttribute("role", "img");
  root.innerHTML = GLYPHS;
  let live: HTMLElement | undefined;
  if (options.announce) {
    live = document.createElement("span");
    live.className = "visually-hidden";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    root.append(live);
  }

  let base: ConnectionIndicatorState = "connecting";
  let detail: string | undefined;
  let queued = 0;
  let rtt: number | undefined;
  let slow = false;
  let shown: ConnectionIndicatorState | undefined;
  let settle = 0;
  let sentence = "";
  let touch = false;
  let lastBreath = -Infinity;

  const effective = (): ConnectionIndicatorState => (base === "connected" && slow ? "slow" : base);
  const render = (): void => {
    const next = effective();
    const text = connectionSentence(next, rtt, detail, queued);
    // Keys waiting to be sent show as one small amber key on the glyph, only while the link is down or coming back.
    if (queued > 0 && (next === "offline" || next === "reconnecting")) root.dataset.queued = ""; else delete root.dataset.queued;
    const changed = next !== shown;
    shown = next;
    root.dataset.state = next;
    // The breath plays once per entry into "slow" (the animation is finite): start it again by switching to its twin
    // (`getAnimations()` would flush style for the whole document, and a page with many terminals samples round trips
    // all the time, so the state can flap), and not more often than the breath lasts.
    if (changed && next === "slow" && performance.now() - lastBreath > BREATH_MS) { lastBreath = performance.now(); root.dataset.breath = root.dataset.breath === "1" ? "0" : "1"; }
    // The glyph a state uses: slow and connected are two colourings of the same dot.
    if (text !== sentence) {
      sentence = text;
      root.dataset.tip = text;
      root.setAttribute("aria-label", text);
      refreshTip(root);
      // A changing round-trip number is not news; a changed state is.
      if (live && changed) live.textContent = text;
    }
  };

  const set = (state: ConnectionIndicatorState, reason?: string, held = 0): void => {
    window.clearTimeout(settle);
    base = state;
    detail = reason;
    queued = held;
    if (state !== "connected") slow = false;
    render();
    const after = SETTLE_MS[state];
    // Settling is the point of these two: the mark says "this just happened", then gets out of the way.
    if (after !== undefined) settle = window.setTimeout(() => set("connected"), after);
  };
  const setRoundTrip = (ms: number | undefined): void => {
    rtt = ms;
    if (ms === undefined) slow = false;
    else if (ms >= slowAt) slow = true;
    else if (ms < slowAt - 60) slow = false;
    render();
  };

  const onPointerDown = (event: PointerEvent): void => { touch = event.pointerType === "touch"; };
  const onClick = (event: MouseEvent): void => {
    if (!touch) return;
    touch = false;
    event.stopPropagation();
    event.preventDefault();
    peekTip(root);
  };
  root.addEventListener("pointerdown", onPointerDown, true);
  root.addEventListener("click", onClick);
  render();

  return {
    root,
    get state() { return shown ?? base; },
    set,
    setRoundTrip,
    dispose() {
      window.clearTimeout(settle);
      root.removeEventListener("pointerdown", onPointerDown, true);
      root.removeEventListener("click", onClick);
      root.remove();
    },
  };
}
